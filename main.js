import { createClientFromRequest } from 'npm:@base44/sdk@0.6.0';

// --- GÜVENLİK KONTROLÜ ---
function authenticateRequest(req) {
    const expectedApiKey = Deno.env.get("BASE44_API_KEY");
    if (!expectedApiKey) {
        const message = "CRITICAL: DENO_API_KEY environment variable is not set on Deno Deploy!";
        console.error(message);
        return {
            message,
            isCorrect: false
        };
    }
    
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        const message = "No Authorization header found or it does not start with 'Bearer '";
        return {
            message,
            isCorrect: false
        };
    }

    const providedKey = authHeader.substring(7);
    const isCorrect = providedKey === expectedApiKey;

    if (!isCorrect) {
        console.warn("Authentication failed. Provided key does not match expected key.");
    }
    
    return {
        providedKey,
        expectedApiKey,
        isCorrect
    };
}

// --- AMAZON SP-API HELPER FUNCTIONS ---
async function exchangeCodeForTokens(code, redirectUri) {
    const clientId = Deno.env.get("AMAZON_CLIENT_ID");
    const clientSecret = Deno.env.get("AMAZON_CLIENT_SECRET");
    if (!clientId || !clientSecret) {
        throw new Error("Amazon LWA credentials are not configured on the server.");
    }
    
    const response = await fetch('https://api.amazon.com/auth/o2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: redirectUri,
            client_id: clientId,
            client_secret: clientSecret,
        }),
    });
    
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Failed to exchange code for tokens: ${errorData.error_description || response.status}`);
    }
    
    return response.json();
}

async function getAmazonAccessToken(refreshToken) {
    const clientId = Deno.env.get("AMAZON_CLIENT_ID");
    const clientSecret = Deno.env.get("AMAZON_CLIENT_SECRET");
    
    const response = await fetch('https://api.amazon.com/auth/o2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: clientId,
            client_secret: clientSecret,
        }),
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Token refresh failed: ${response.status} - ${errorText}`);
    }
    
    return response.json();
}

async function makeAmazonAPIRequest(endpoint, accessToken, region = 'NA') {
    const baseUrls = {
        'NA': 'https://sellingpartnerapi-na.amazon.com',
        'EU': 'https://sellingpartnerapi-eu.amazon.com',
        'FE': 'https://sellingpartnerapi-fe.amazon.com'
    };
    
    const response = await fetch(`${baseUrls[region]}${endpoint}`, {
        headers: { 
            'x-amz-access-token': accessToken, 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        }
    });
    
    if (response.status === 403) {
        throw new Error('Token expired or invalid');
    }
    
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Amazon API request failed: ${response.status} - ${errorText}`);
    }
    
    return response.json();
}

// --- AMAZON ORDER ITEMS FETCHER ---
async function fetchOrderItems(amazonOrderId, accessToken, region) {
    try {
        const endpoint = `/orders/v0/orders/${amazonOrderId}/orderItems`;
        const itemsResponse = await makeAmazonAPIRequest(endpoint, accessToken, region);
        return itemsResponse.payload?.OrderItems || [];
    } catch (error) {
        console.warn(`Failed to fetch items for order ${amazonOrderId}:`, error.message);
        return [];
    }
}

// --- SİPARİŞ SENKRONİZASYON İÇ FONKSİYONU ---
async function syncUserOrdersInternal(db, userId, connection) {
    console.log(`Starting order sync for user: ${userId}, connection: ${connection.id}`);
    
    let currentAccessToken = connection.access_token;
    
    // Token süresi dolduysa yenile
    if (new Date(connection.token_expires_at) <= new Date()) {
        console.log('Access token expired, refreshing...');
        try {
            const newTokens = await getAmazonAccessToken(connection.refresh_token);
            currentAccessToken = newTokens.access_token;
            
            await db.UserConnection.update(connection.id, {
                access_token: newTokens.access_token,
                token_expires_at: new Date(Date.now() + (newTokens.expires_in || 3600) * 1000).toISOString()
            });
            
            console.log('Access token refreshed successfully');
        } catch (tokenError) {
            console.error('Token refresh failed:', tokenError);
            await db.UserConnection.update(connection.id, { status: 'error' });
            throw new Error(`Token refresh failed for connection ${connection.id}: ${tokenError.message}`);
        }
    }

    // Kullanıcının aktif marketplaces'lerini al
    const marketplaces = await db.UserMarketplace.filter({ user_id: userId, is_active: true });
    if (marketplaces.length === 0) {
        console.log('No active marketplaces found for user');
        return { found: 0, synced: 0, updated: 0 };
    }
    
    const marketplaceIds = marketplaces.map(m => m.marketplace_id).join(',');
    
    // Son 30 günün siparişlerini al
    const createdAfter = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const ordersEndpoint = `/orders/v0/orders?MarketplaceIds=${marketplaceIds}&CreatedAfter=${createdAfter}`;
    
    console.log(`Fetching orders from Amazon API: ${ordersEndpoint}`);
    
    const ordersResponse = await makeAmazonAPIRequest(ordersEndpoint, currentAccessToken, connection.region);
    const amazonOrders = ordersResponse.payload?.Orders || [];
    
    console.log(`Found ${amazonOrders.length} orders from Amazon`);

    // Mevcut siparişleri kontrol et
    const existingOrders = await db.Order.filter({ created_by: userId });
    const existingOrderIds = new Set(existingOrders.map(o => o.amazon_order_id));
    
    let syncedCount = 0, updatedCount = 0;

    for (const amazonOrder of amazonOrders) {
        try {
            // Sipariş items'larını al
            const orderItems = await fetchOrderItems(amazonOrder.AmazonOrderId, currentAccessToken, connection.region);
            
            if (existingOrderIds.has(amazonOrder.AmazonOrderId)) {
                // Mevcut sipariş - güncelleme gerekli mi kontrol et
                const existing = existingOrders.find(o => o.amazon_order_id === amazonOrder.AmazonOrderId);
                if (existing && (
                    existing.order_status !== amazonOrder.OrderStatus ||
                    existing.number_of_items_shipped !== amazonOrder.NumberOfItemsShipped
                )) {
                    await db.Order.update(existing.id, {
                        order_status: amazonOrder.OrderStatus,
                        last_update_date: amazonOrder.LastUpdateDate,
                        number_of_items_shipped: amazonOrder.NumberOfItemsShipped || 0,
                        number_of_items_unshipped: amazonOrder.NumberOfItemsUnshipped || 0,
                        items: orderItems.map(item => ({
                            order_item_id: item.OrderItemId,
                            asin: item.ASIN,
                            seller_sku: item.SellerSKU,
                            title: item.Title,
                            quantity_ordered: item.QuantityOrdered || 0,
                            quantity_shipped: item.QuantityShipped || 0,
                            item_price: item.ItemPrice?.Amount ? parseFloat(item.ItemPrice.Amount) : 0,
                            currency: item.ItemPrice?.CurrencyCode || amazonOrder.OrderTotal?.CurrencyCode || 'USD'
                        }))
                    });
                    updatedCount++;
                }
            } else {
                // Yeni sipariş - ekle
                await db.Order.create({
                    created_by: userId,
                    amazon_order_id: amazonOrder.AmazonOrderId,
                    purchase_date: amazonOrder.PurchaseDate,
                    last_update_date: amazonOrder.LastUpdateDate,
                    order_status: amazonOrder.OrderStatus,
                    order_total: amazonOrder.OrderTotal,
                    marketplace_id: amazonOrder.MarketplaceId,
                    number_of_items_shipped: amazonOrder.NumberOfItemsShipped || 0,
                    number_of_items_unshipped: amazonOrder.NumberOfItemsUnshipped || 0,
                    shipping_address: amazonOrder.ShippingAddress,
                    buyer_info: amazonOrder.BuyerInfo,
                    fulfillment_channel: amazonOrder.FulfillmentChannel,
                    sales_channel: amazonOrder.SalesChannel,
                    is_prime: amazonOrder.IsPrime || false,
                    is_business_order: amazonOrder.IsBusinessOrder || false,
                    items: orderItems.map(item => ({
                        order_item_id: item.OrderItemId,
                        asin: item.ASIN,
                        seller_sku: item.SellerSKU,
                        title: item.Title,
                        quantity_ordered: item.QuantityOrdered || 0,
                        quantity_shipped: item.QuantityShipped || 0,
                        item_price: item.ItemPrice?.Amount ? parseFloat(item.ItemPrice.Amount) : 0,
                        currency: item.ItemPrice?.CurrencyCode || amazonOrder.OrderTotal?.CurrencyCode || 'USD'
                    }))
                });
                syncedCount++;
            }
        } catch (orderError) {
            console.error(`Failed to process order ${amazonOrder.AmazonOrderId}:`, orderError.message);
            // Tek sipariş hatası tüm sync'i durdurmasın, devam et
        }
    }
    
    console.log(`Sync completed: ${syncedCount} new, ${updatedCount} updated`);
    return { found: amazonOrders.length, synced: syncedCount, updated: updatedCount };
}

// --- ANA DENO FONKSİYONU ---
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
        const authResult = authenticateRequest(req);
        if (!authResult.isCorrect) {
            return new Response(JSON.stringify({ 
                error: "Unauthorized",
                message: authResult.message,
                details: authResult.providedKey ? {
                    providedKeyPrefix: authResult.providedKey.substring(0, 4) + '...',
                    expectedKeyPrefix: authResult.expectedApiKey ? authResult.expectedApiKey.substring(0, 4) + '...' : 'NOT SET'
                } : 'No key provided in Authorization header'
            }), { 
                status: 401, 
                headers: corsHeaders 
            });
        }

        const base44 = createClientFromRequest(req, {
            appId: Deno.env.get("BASE44_APP_ID"),
            serviceToken: Deno.env.get("BASE44_API_KEY")
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
        
        console.log(`Received action: ${action}, params:`, params);

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

            // === AMAZON YETKİLENDİRME KODU DEĞİŞİMİ ===
            case 'exchangeCodeForTokens':
                const { userId, spapi_oauth_code, selling_partner_id, redirect_uri } = params;
                
                if (!userId || !spapi_oauth_code || !selling_partner_id) {
                    return new Response(JSON.stringify({ 
                        error: "Missing required parameters: userId, spapi_oauth_code, selling_partner_id" 
                    }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                try {
                    const tokenData = await exchangeCodeForTokens(spapi_oauth_code, redirect_uri);
                    
                    // Bölgeyi selling partner ID'den belirle
                    const region = selling_partner_id.startsWith('A') ? 'NA' : 
                                  (selling_partner_id.startsWith('E') ? 'EU' : 'FE');

                    await db.UserConnection.create({
                        user_id: userId,
                        region: region,
                        selling_partner_id: selling_partner_id,
                        access_token: tokenData.access_token,
                        refresh_token: tokenData.refresh_token,
                        token_expires_at: new Date(Date.now() + (tokenData.expires_in || 3600) * 1000).toISOString(),
                        status: 'active'
                    });
                    
                    return new Response(JSON.stringify({ 
                        success: true, 
                        message: "Amazon connection successful" 
                    }), { headers: corsHeaders });
                    
                } catch (error) {
                    console.error('Exchange code error:', error);
                    return new Response(JSON.stringify({ 
                        error: "Failed to exchange authorization code",
                        details: error.message 
                    }), { 
                        status: 500, 
                        headers: corsHeaders 
                    });
                }

            // === KULLANICI SİPARİŞLERİNİ SENKRONİZE ET ===
            case 'syncUserOrders':
                const { userEmail: syncUserEmail, connectionId } = params;
                
                if (!syncUserEmail) {
                    return new Response(JSON.stringify({ error: "userEmail is required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                try {
                    const users = await db.User.filter({ email: syncUserEmail });
                    if (!users || users.length === 0) {
                        return new Response(JSON.stringify({ error: "User not found" }), { 
                            status: 404, 
                            headers: corsHeaders 
                        });
                    }

                    const currentUser = users[0];
                    let userConnection;

                    if (connectionId) {
                        userConnection = await db.UserConnection.get(connectionId);
                        if (!userConnection || userConnection.user_id !== currentUser.id) {
                            return new Response(JSON.stringify({ error: "Connection not found or not authorized" }), { 
                                status: 404, 
                                headers: corsHeaders 
                            });
                        }
                    } else {
                        const connections = await db.UserConnection.filter({ 
                            user_id: currentUser.id, 
                            status: 'active' 
                        });
                        if (connections.length === 0) {
                            return new Response(JSON.stringify({ 
                                success: true, 
                                message: "No active Amazon connections found for this user" 
                            }), { headers: corsHeaders });
                        }
                        userConnection = connections[0]; // İlk aktif bağlantıyı kullan
                    }

                    const results = await syncUserOrdersInternal(db, currentUser.id, userConnection);
                    
                    return new Response(JSON.stringify({ 
                        success: true, 
                        message: `Sync completed successfully`,
                        ...results
                    }), { headers: corsHeaders });

                } catch (error) {
                    console.error('Sync user orders error:', error);
                    return new Response(JSON.stringify({ 
                        error: "Failed to sync user orders",
                        details: error.message 
                    }), { 
                        status: 500, 
                        headers: corsHeaders 
                    });
                }

            // === TOPLU SİPARİŞ SENKRONİZASYONU (SADECE SİSTEM ADMİNLERİ) ===
            case 'syncAllOrders':
                const { userEmail } = params;
                
                if (!userEmail) {
                    return new Response(JSON.stringify({ error: "userEmail is required" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                try {
                    const users = await db.User.filter({ email: userEmail });
                    if (!users || users.length === 0) {
                        return new Response(JSON.stringify({ error: "User not found" }), { 
                            status: 404, 
                            headers: corsHeaders 
                        });
                    }

                    const currentUser = users[0];
                    if (currentUser.role !== 'system_admin' && currentUser.role !== 'admin') {
                        return new Response(JSON.stringify({ 
                            error: 'Unauthorized: Only system admins can perform this action' 
                        }), { 
                            status: 403, 
                            headers: corsHeaders 
                        });
                    }

                    // Tüm aktif bağlantıları al
                    const activeConnections = await db.UserConnection.filter({ status: 'active' });
                    
                    if (activeConnections.length === 0) {
                        return new Response(JSON.stringify({ 
                            success: true, 
                            message: "No active connections to sync.",
                            processedConnections: 0,
                            totalConnections: 0,
                            totalFound: 0,
                            totalSynced: 0,
                            totalUpdated: 0
                        }), { headers: corsHeaders });
                    }

                    let totalFound = 0, totalSynced = 0, totalUpdated = 0;
                    let processedConnections = 0;

                    for (const connection of activeConnections) {
                        try {
                            const results = await syncUserOrdersInternal(db, connection.user_id, connection);
                            totalFound += results.found;
                            totalSynced += results.synced;
                            totalUpdated += results.updated;
                            processedConnections++;
                            
                            console.log(`Processed connection ${connection.id}: +${results.synced} new, +${results.updated} updated`);
                        } catch (error) {
                            console.error(`Failed to sync connection ${connection.id}:`, error.message);
                            // Bir bağlantı başarısız olursa devam et
                        }
                    }

                    return new Response(JSON.stringify({ 
                        success: true, 
                        message: "Bulk sync completed",
                        processedConnections,
                        totalConnections: activeConnections.length,
                        totalFound,
                        totalSynced,
                        totalUpdated
                    }), { headers: corsHeaders });

                } catch (error) {
                    console.error('Sync all orders error:', error);
                    return new Response(JSON.stringify({ 
                        error: "Failed to sync all orders",
                        details: error.message 
                    }), { 
                        status: 500, 
                        headers: corsHeaders 
                    });
                }

            // === DEBUG: VERITABANI DURUMU KONTROLÜ ===
            case 'debug':
                const { userEmail: debugUserEmail } = params;
                if (!debugUserEmail) {
                    return new Response(JSON.stringify({ error: "userEmail is required for debug" }), { 
                        status: 400, 
                        headers: corsHeaders 
                    });
                }

                const allConnections = await db.UserConnection.list();
                const allUsers = await db.User.list();
                const targetUser = await db.User.filter({ email: debugUserEmail });

                return new Response(JSON.stringify({
                    success: true,
                    debug_info: {
                        total_users: allUsers.length,
                        target_user: targetUser[0] || 'Not found',
                        total_connections: allConnections.length,
                        connections: allConnections,
                        sample_connection: allConnections[0] || 'No connections exist',
                        environment: {
                            hasAppId: !!Deno.env.get("BASE44_APP_ID"),
                            hasApiKey: !!Deno.env.get("BASE44_API_KEY"),
                            hasDenoKey: !!Deno.env.get("DENO_API_KEY"),
                            hasAmazonClientId: !!Deno.env.get("AMAZON_CLIENT_ID"),
                            hasAmazonSecret: !!Deno.env.get("AMAZON_CLIENT_SECRET")
                        }
                    }
                }), { headers: corsHeaders });
                
            default:
                return new Response(JSON.stringify({ error: `Invalid action: ${action}` }), { 
                    status: 400, 
                    headers: corsHeaders 
                });
        }
        
    } catch (error) {
        console.error(`Deno Function Error:`, error);
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
