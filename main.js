import { createClientFromRequest } from 'npm:@base44/sdk@0.5.0';

// --- GÜVENLİK KONTROLÜ ---
function authenticateRequest(req) {
    const expectedApiKey = Deno.env.get("DENO_API_KEY");
    if (!expectedApiKey) {
        console.error("CRITICAL: DENO_API_KEY environment variable is not set on Deno Deploy!");
        return false;
    }
    
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return false;
    }

    const providedKey = authHeader.substring(7);
    return providedKey === expectedApiKey;
}

// --- AMAZON SP-API HELPER FUNCTIONS ---
async function getAmazonAccessToken(refreshToken, clientId, clientSecret) {
    try {
        const response = await fetch('https://api.amazon.com/auth/o2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'grant_type': 'refresh_token',
                'refresh_token': refreshToken,
                'client_id': clientId,
                'client_secret': clientSecret,
            }),
        });

        if (!response.ok) {
            throw new Error(`Token refresh failed: ${response.status}`);
        }

        const tokenData = await response.json();
        return tokenData.access_token;
    } catch (error) {
        console.error('Error refreshing Amazon token:', error);
        throw error;
    }
}

async function makeAmazonAPIRequest(endpoint, accessToken, region = 'NA') {
    const baseUrls = {
        'NA': 'https://sellingpartnerapi-na.amazon.com',
        'EU': 'https://sellingpartnerapi-eu.amazon.com',
        'FE': 'https://sellingpartnerapi-fe.amazon.com'
    };

    try {
        const response = await fetch(`${baseUrls[region]}${endpoint}`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'x-amz-access-token': accessToken,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Amazon API request failed: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Error making Amazon API request:', error);
        throw error;
    }
}

// --- ANA FONKSİYON ---
Deno.serve(async (req) => {
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Type': 'application/json'
    };

    if (req.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
        if (!authenticateRequest(req)) {
            return new Response(JSON.stringify({ error: "Unauthorized" }), { 
                status: 401, 
                headers: corsHeaders 
            });
        }

        const base44 = createClientFromRequest(req, {
            appId: Deno.env.get("BASE44_APP_ID"),
            apiKey: Deno.env.get("BASE44_API_KEY")
        });
        const db = base44.asServiceRole.entities;

        let payload = {};
        try {
            payload = await req.json();
        } catch (e) {
            return new Response(JSON.stringify({ error: "Invalid JSON in request body" }), { 
                status: 400, 
                headers: corsHeaders 
            });
        }

        const { action, params = {} } = payload;

        switch (action) {
            // === TEST FONKSİYONU ===
            case 'test':
                return new Response(JSON.stringify({
                    success: true,
                    message: "Deno function is working perfectly!",
                    timestamp: new Date().toISOString(),
                    environment: {
                        hasAppId: !!Deno.env.get("BASE44_APP_ID"),
                        hasApiKey: !!Deno.env.get("BASE44_API_KEY"),
                        hasDenoKey: !!Deno.env.get("DENO_API_KEY"),
                        hasAmazonClientId: !!Deno.env.get("AMAZON_CLIENT_ID"),
                        hasAmazonSecret: !!Deno.env.get("AMAZON_CLIENT_SECRET")
                    }
                }), { headers: corsHeaders });

            // === TOPLU SİPARİŞ SENKRONİZASYONU ===
            case 'syncAllOrders':
                const { userEmail } = params;
                if (!userEmail) {
                    return new Response(JSON.stringify({ error: "userEmail is required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                const users = await db.User.filter({ email: userEmail });
                if (!users || users.length === 0) {
                    return new Response(JSON.stringify({ error: "User not found" }), { 
                        status: 404, 
                        headers: corsHeaders 
                    });
                }

                const currentUser = users[0];
                if (currentUser.role !== 'system_admin') {
                    return new Response(JSON.stringify({ 
                        error: 'Unauthorized: Only system admins can perform this action' 
                    }), { 
                        status: 403, 
                        headers: corsHeaders 
                    });
                }

                // Tüm aktif bağlantıları al
                const activeConnections = await db.UserConnection.filter({ status: 'active' });
                let totalProcessed = 0;
                let totalFound = 0;
                let totalSynced = 0;
                let totalUpdated = 0;

                for (const connection of activeConnections) {
                    try {
                        // Her bağlantı için siparişleri senkronize et
                        const result = await syncUserOrdersInternal(db, connection.user_id, connection);
                        totalProcessed++;
                        totalFound += result.found;
                        totalSynced += result.synced;
                        totalUpdated += result.updated;
                    } catch (error) {
                        console.error(`Error syncing orders for user ${connection.user_id}:`, error);
                    }
                }

                return new Response(JSON.stringify({
                    success: true,
                    message: "Bulk sync completed",
                    processedConnections: totalProcessed,
                    totalConnections: activeConnections.length,
                    totalFound,
                    totalSynced,
                    totalUpdated
                }), { headers: corsHeaders });

            // === TEK KULLANICI SİPARİŞ SENKRONİZASYONU ===
            case 'syncUserOrders':
                const { userId, connectionId } = params;
                if (!userId) {
                    return new Response(JSON.stringify({ error: "userId is required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                let userConnection;
                if (connectionId) {
                    userConnection = await db.UserConnection.get(connectionId);
                } else {
                    const connections = await db.UserConnection.filter({ 
                        user_id: userId, 
                        status: 'active' 
                    });
                    userConnection = connections[0];
                }

                if (!userConnection) {
                    return new Response(JSON.stringify({ error: "Active connection not found" }), { 
                        status: 404, 
                        headers: corsHeaders 
                    });
                }

                const syncResult = await syncUserOrdersInternal(db, userId, userConnection);
                return new Response(JSON.stringify({
                    success: true,
                    ...syncResult
                }), { headers: corsHeaders });

            // === SİPARİŞ DETAYLARINI ALMA ===
            case 'getOrderItems':
                const { orderId, userId: orderUserId } = params;
                if (!orderId || !orderUserId) {
                    return new Response(JSON.stringify({ error: "orderId and userId are required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                // Mock response - gerçek implementasyon Amazon SP-API çağrısı yapacak
                const orderItems = [
                    {
                        orderItemId: "12345678901234",
                        asin: "B08N5WRWNW",
                        sellerSku: "MY-SKU-001",
                        title: "Example Product",
                        quantityOrdered: 1,
                        itemPrice: { currencyCode: "USD", amount: "29.99" },
                        itemTax: { currencyCode: "USD", amount: "2.40" }
                    }
                ];

                return new Response(JSON.stringify({
                    success: true,
                    orderItems
                }), { headers: corsHeaders });

            // === ÜRÜN BİLGİLERİNİ ALMA ===
            case 'getProducts':
                const { marketplaceId, userId: productUserId } = params;
                if (!marketplaceId || !productUserId) {
                    return new Response(JSON.stringify({ error: "marketplaceId and userId are required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                // Mock response - gerçek implementasyon Amazon SP-API çağrısı yapacak
                const products = [
                    {
                        asin: "B08N5WRWNW",
                        sellerSku: "MY-SKU-001",
                        title: "Example Product",
                        brand: "Example Brand",
                        category: "Electronics",
                        listPrice: { currencyCode: "USD", amount: "39.99" },
                        landedPrice: { currencyCode: "USD", amount: "29.99" }
                    }
                ];

                return new Response(JSON.stringify({
                    success: true,
                    products
                }), { headers: corsHeaders });

            // === TOKEN YENİLEME ===
            case 'refreshTokens':
                const { connectionId: refreshConnectionId } = params;
                if (!refreshConnectionId) {
                    return new Response(JSON.stringify({ error: "connectionId is required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                const connection = await db.UserConnection.get(refreshConnectionId);
                if (!connection) {
                    return new Response(JSON.stringify({ error: "Connection not found" }), { 
                        status: 404, 
                        headers: corsHeaders 
                    });
                }

                try {
                    const clientId = Deno.env.get("AMAZON_CLIENT_ID");
                    const clientSecret = Deno.env.get("AMAZON_CLIENT_SECRET");
                    
                    if (!clientId || !clientSecret) {
                        throw new Error("Amazon credentials not configured");
                    }

                    const newAccessToken = await getAmazonAccessToken(
                        connection.refresh_token,
                        clientId,
                        clientSecret
                    );

                    // Token'ı güncelle
                    await db.UserConnection.update(refreshConnectionId, {
                        access_token: newAccessToken,
                        token_expires_at: new Date(Date.now() + 3600 * 1000).toISOString() // 1 saat
                    });

                    return new Response(JSON.stringify({
                        success: true,
                        message: "Tokens refreshed successfully"
                    }), { headers: corsHeaders });

                } catch (error) {
                    await db.UserConnection.update(refreshConnectionId, {
                        status: 'error'
                    });

                    return new Response(JSON.stringify({
                        success: false,
                        error: "Token refresh failed",
                        details: error.message
                    }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

            // === SİPARİŞ DURUMU GÜNCELLEME ===
            case 'updateOrderStatus':
                const { amazonOrderId, newStatus, trackingNumber } = params;
                if (!amazonOrderId || !newStatus) {
                    return new Response(JSON.stringify({ error: "amazonOrderId and newStatus are required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                // Siparişi bul ve güncelle
                const orders = await db.Order.filter({ amazon_order_id: amazonOrderId });
                if (orders.length > 0) {
                    const updateData = { order_status: newStatus };
                    if (trackingNumber) {
                        updateData.tracking_number = trackingNumber;
                    }
                    
                    await db.Order.update(orders[0].id, updateData);
                }

                return new Response(JSON.stringify({
                    success: true,
                    message: "Order status updated"
                }), { headers: corsHeaders });

            // === PAZARYERI BİLGİLERİNİ ALMA ===
            case 'getMarketplaces':
                const marketplaces = {
                    'NA': [
                        { id: 'ATVPDKIKX0DER', name: 'United States', country: 'US' },
                        { id: 'A2EUQ1WTGCTBG2', name: 'Canada', country: 'CA' },
                        { id: 'A1AM78C64UM0Y8', name: 'Mexico', country: 'MX' }
                    ],
                    'EU': [
                        { id: 'A1F83G8C2ARO7P', name: 'United Kingdom', country: 'UK' },
                        { id: 'A1PA6795UKMFR9', name: 'Germany', country: 'DE' },
                        { id: 'A13V1IB3VIYZZH', name: 'France', country: 'FR' }
                    ],
                    'FE': [
                        { id: 'A1VC38T7YXB528', name: 'Japan', country: 'JP' },
                        { id: 'A39IBJ37TRP1C6', name: 'Australia', country: 'AU' }
                    ]
                };

                return new Response(JSON.stringify({
                    success: true,
                    marketplaces
                }), { headers: corsHeaders });

            default:
                return new Response(JSON.stringify({ 
                    error: `Invalid action: ${action}`,
                    availableActions: [
                        'test', 'syncAllOrders', 'syncUserOrders', 
                        'getOrderItems', 'getProducts', 'refreshTokens', 
                        'updateOrderStatus', 'getMarketplaces'
                    ]
                }), { 
                    status: 400, 
                    headers: corsHeaders 
                });
        }
    } catch (error) {
        console.error(`Error processing request:`, error);
        return new Response(JSON.stringify({ 
            error: "An internal server error occurred in Deno Deploy function.", 
            details: error.message,
            stack: error.stack
        }), { 
            status: 500, 
            headers: corsHeaders 
        });
    }
});

// === YARDIMCI FONKSİYONLAR ===

async function syncUserOrdersInternal(db, userId, connection) {
    try {
        // Mock implementation - gerçek Amazon SP-API entegrasyonu burada olacak
        
        // 1. Token'ı yenile (gerekirse)
        const now = new Date();
        const expiresAt = new Date(connection.token_expires_at);
        
        if (expiresAt <= now) {
            // Token süresi dolmuş, yenile
            const clientId = Deno.env.get("AMAZON_CLIENT_ID");
            const clientSecret = Deno.env.get("AMAZON_CLIENT_SECRET");
            
            if (clientId && clientSecret) {
                try {
                    const newAccessToken = await getAmazonAccessToken(
                        connection.refresh_token,
                        clientId,
                        clientSecret
                    );
                    
                    await db.UserConnection.update(connection.id, {
                        access_token: newAccessToken,
                        token_expires_at: new Date(Date.now() + 3600 * 1000).toISOString()
                    });
                } catch (error) {
                    console.error('Token refresh failed:', error);
                    throw new Error('Token refresh failed');
                }
            }
        }

        // 2. Amazon'dan siparişleri çek
        // Bu gerçek implementasyonda Amazon SP-API çağrısı olacak
        
        // 3. Veritabanında mevcut siparişleri kontrol et ve güncelle
        const existingOrders = await db.Order.filter({ created_by: userId });
        const existingOrderIds = new Set(existingOrders.map(o => o.amazon_order_id));

        // Mock data - gerçek Amazon API'den gelecek
        const amazonOrders = [
            {
                amazonOrderId: `902-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                purchaseDate: new Date().toISOString(),
                orderStatus: 'Unshipped',
                orderTotal: { currencyCode: 'USD', amount: '29.99' },
                marketplaceId: 'ATVPDKIKX0DER'
            }
        ];

        let syncedCount = 0;
        let updatedCount = 0;

        for (const amazonOrder of amazonOrders) {
            if (existingOrderIds.has(amazonOrder.amazonOrderId)) {
                // Mevcut sipariş - güncelle
                const existing = existingOrders.find(o => o.amazon_order_id === amazonOrder.amazonOrderId);
                if (existing.order_status !== amazonOrder.orderStatus) {
                    await db.Order.update(existing.id, {
                        order_status: amazonOrder.orderStatus,
                        last_update_date: new Date().toISOString()
                    });
                    updatedCount++;
                }
            } else {
                // Yeni sipariş - ekle
                await db.Order.create({
                    amazon_order_id: amazonOrder.amazonOrderId,
                    purchase_date: amazonOrder.purchaseDate,
                    order_status: amazonOrder.orderStatus,
                    order_total: amazonOrder.orderTotal,
                    marketplace_id: amazonOrder.marketplaceId,
                    created_by: userId
                });
                syncedCount++;
            }
        }

        return {
            found: amazonOrders.length,
            synced: syncedCount,
            updated: updatedCount
        };

    } catch (error) {
        console.error('Error in syncUserOrdersInternal:', error);
        throw error;
    }
}
