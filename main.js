
// --- GÜVENLİK KONTROLÜ ---
function authenticateRequest(req) {
    const expectedApiKey = Deno.env.get("BASE44_API_KEY");
    if (!expectedApiKey) {
        const message = "CRITICAL: BASE44_API_KEY environment variable is not set on Deno Deploy!";
        console.error(message);
        return {
            message,
            isCorrect: false
        };
    }
    
    const authHeader = req.headers.get("Base44-Service-Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        const message = "No Base44-Service-Authorization header found or it does not start with 'Bearer '";
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

// --- BASE44 API HELPER CLASS (Filtresiz) ---
class Base44API {
    constructor(appId, apiKey) {
        this.appId = appId;
        this.apiKey = apiKey;
        this.baseUrl = `https://base44.app/api/apps/${appId}`;
    }

    async request(endpoint, method = 'GET', body = null) {
        const url = `${this.baseUrl}${endpoint}`;
        const options = {
            method,
            headers: {
                'api_key': this.apiKey,
                'Content-Type': 'application/json'
            }
        };

        if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
            options.body = JSON.stringify(body);
        }

        console.log(`Making API request: ${method} ${url}`);
        const response = await fetch(url, options);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Base44 API Error: ${response.status} - ${errorText} - ${url}`);
        }
        
        return response.json();
    }

    // Entity operations (filters parametresi kaldırıldı)
    async getEntityRecords(entityName, sort = null, limit = null, offset = null) {
        let query = `/entities/${entityName}`;
        const params = new URLSearchParams();
        
        if (sort) params.append('sort', sort);
        if (limit) params.append('limit', limit.toString());
        if (offset) params.append('offset', offset.toString());
        
        if (params.toString()) {
            query += `?${params.toString()}`;
        }
        
        return this.request(query);
    }

    async createEntityRecord(entityName, data) {
        return this.request(`/entities/${entityName}`, 'POST', data);
    }

    async updateEntityRecord(entityName, recordId, data) {
        return this.request(`/entities/${entityName}/${recordId}`, 'PATCH', data);
    }

    async getEntityRecord(entityName, recordId) {
        return this.request(`/entities/${entityName}/${recordId}`);
    }

    async deleteEntityRecord(entityName, recordId) {
        return this.request(`/entities/${entityName}/${recordId}`, 'DELETE');
    }
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


// --- SİPARİŞ SENKRONİZASYON İÇ FONKSİYONU (Manuel Filtreleme ile) ---
async function syncUserOrdersInternal(api, userId, connection) {
    console.log(`Starting order sync for user ID: ${userId}, connection: ${connection.id}`);
    
    let currentAccessToken = connection.access_token;
    
    // Token süresi dolduysa yenile
    if (new Date(connection.token_expires_at) <= new Date()) {
        console.log('Access token expired, refreshing...');
        try {
            const newTokens = await getAmazonAccessToken(connection.refresh_token);
            currentAccessToken = newTokens.access_token;
            
            await api.updateEntityRecord('UserConnection', connection.id, {
                access_token: currentAccessToken,
                token_expires_at: new Date(Date.now() + 3600 * 1000).toISOString()
            });
            
            console.log('Access token refreshed successfully');
        } catch (error) {
            console.error('Token refresh failed:', error);
            throw new Error('Token refresh failed');
        }
    }

    // Get ALL marketplaces and filter in-memory
    const allMarketplaces = await api.getEntityRecords('UserMarketplace');
    const userMarketplaces = allMarketplaces.filter(m => m.user_id === userId && m.is_active);
    
    if (userMarketplaces.length === 0) {
        console.log('No active marketplaces found for user');
        return { totalFound: 0, totalSynced: 0, totalUpdated: 0 };
    }
    
    // Pre-fetch all orders for this user to avoid repeated full scans
    // WARNING: This is inefficient as it fetches ALL orders from the DB.
    // This is a workaround because API filtering is not working.
    const allOrdersInDB = await api.getEntityRecords('Order');
    const userOrdersInDB = allOrdersInDB.filter(o => o.created_by === userId);

    let totalFound = 0;
    let totalSynced = 0;
    let totalUpdated = 0;

    // Her marketplace için siparişleri çek
    for (const marketplace of userMarketplaces) {
        try {
            console.log(`Syncing orders for marketplace: ${marketplace.marketplace_id}`);
            
            const createdAfter = new Date();
            createdAfter.setDate(createdAfter.getDate() - 30); // Son 30 gün
            
            const endpoint = `/orders/v0/orders?CreatedAfter=${createdAfter.toISOString()}&MarketplaceIds=${marketplace.marketplace_id}`;
            const ordersResponse = await makeAmazonAPIRequest(endpoint, currentAccessToken, connection.region);
            
            const amazonOrders = ordersResponse.payload?.Orders || [];
            totalFound += amazonOrders.length;
            
            for (const amazonOrder of amazonOrders) {
                try {
                    // Existing order check (in-memory)
                    const existingOrder = userOrdersInDB.find(o => o.amazon_order_id === amazonOrder.AmazonOrderId);
                    
                    const orderItems = await fetchOrderItems(amazonOrder.AmazonOrderId, currentAccessToken, connection.region);
                    const transformedItems = orderItems.map(item => ({
                        order_item_id: item.OrderItemId,
                        asin: item.ASIN,
                        seller_sku: item.SellerSKU,
                        title: item.Title,
                        quantity_ordered: item.QuantityOrdered,
                        quantity_shipped: item.QuantityShipped || 0,
                        item_price: item.ItemPrice,
                        shipping_price: item.ShippingPrice,
                        item_tax: item.ItemTax,
                        shipping_tax: item.ShippingTax
                    }));

                    const orderData = {
                        amazon_order_id: amazonOrder.AmazonOrderId,
                        seller_order_id: amazonOrder.SellerOrderId,
                        purchase_date: amazonOrder.PurchaseDate,
                        last_update_date: amazonOrder.LastUpdateDate,
                        order_status: amazonOrder.OrderStatus,
                        fulfillment_channel: amazonOrder.FulfillmentChannel,
                        sales_channel: amazonOrder.SalesChannel,
                        order_channel: amazonOrder.OrderChannel,
                        ship_service_level: amazonOrder.ShipServiceLevel,
                        order_total: amazonOrder.OrderTotal,
                        number_of_items_shipped: amazonOrder.NumberOfItemsShipped,
                        number_of_items_unshipped: amazonOrder.NumberOfItemsUnshipped,
                        payment_method: amazonOrder.PaymentMethod,
                        payment_method_details: amazonOrder.PaymentMethodDetails,
                        marketplace_id: amazonOrder.MarketplaceId,
                        shipment_service_level_category: amazonOrder.ShipmentServiceLevelCategory,
                        earliest_ship_date: amazonOrder.EarliestShipDate,
                        latest_ship_date: amazonOrder.LatestShipDate,
                        earliest_delivery_date: amazonOrder.EarliestDeliveryDate,
                        latest_delivery_date: amazonOrder.LatestDeliveryDate,
                        is_business_order: amazonOrder.IsBusinessOrder,
                        is_prime: amazonOrder.IsPrime,
                        is_premium_order: amazonOrder.IsPremiumOrder,
                        is_global_express_enabled: amazonOrder.IsGlobalExpressEnabled,
                        replaced_order_id: amazonOrder.ReplacedOrderId,
                        is_replacement_order: amazonOrder.IsReplacementOrder,
                        promise_response_due_date: amazonOrder.PromiseResponseDueDate,
                        is_estimated_ship_date_set: amazonOrder.IsEstimatedShipDateSet,
                        is_sold_by_ab: amazonOrder.IsSoldByAB,
                        is_iba: amazonOrder.IsIBA,
                        default_ship_from_location_address: amazonOrder.DefaultShipFromLocationAddress,
                        buyer_requested_cancel: amazonOrder.BuyerRequestedCancel,
                        fulfillment_instruction: amazonOrder.FulfillmentInstruction,
                        is_access_point_order: amazonOrder.IsAccessPointOrder,
                        marketplace_tax_info: amazonOrder.MarketplaceTaxInfo,
                        seller_display_name: amazonOrder.SellerDisplayName,
                        shipping_address: amazonOrder.ShippingAddress,
                        buyer_info: amazonOrder.BuyerInfo,
                        automated_shipping_settings: amazonOrder.AutomatedShippingSettings,
                        has_regulated_items: amazonOrder.HasRegulatedItems,
                        electronic_invoice_status: amazonOrder.ElectronicInvoiceStatus,
                        items: transformedItems,
                        created_by: userId
                    };

                    if (existingOrder) {
                        await api.updateEntityRecord('Order', existingOrder.id, orderData);
                        totalUpdated++;
                        console.log(`Updated order: ${amazonOrder.AmazonOrderId}`);
                    } else {
                        await api.createEntityRecord('Order', orderData);
                        totalSynced++;
                        console.log(`Created new order: ${amazonOrder.AmazonOrderId}`);
                    }
                    
                } catch (error) {
                    console.error(`Failed to sync order ${amazonOrder.AmazonOrderId}:`, error.message);
                }
            }
            
        } catch (error) {
            console.error(`Failed to sync marketplace ${marketplace.marketplace_id}:`, error.message);
        }
    }

    return { totalFound, totalSynced, totalUpdated };
}

// --- ANA DENO FONKSİYONU ---
Deno.serve(async (req) => {
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Base44-Service-Authorization',
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
                } : 'No key provided in Base44-Service-Authorization header'
            }), { 
                status: 401, 
                headers: corsHeaders 
            });
        }

        const appId = Deno.env.get("BASE44_APP_ID");
        const apiKey = Deno.env.get("BASE44_API_KEY");
        if (!appId || !apiKey) {
            throw new Error("BASE44_APP_ID or BASE44_API_KEY environment variables are not set");
        }
        const api = new Base44API(appId, apiKey);
        
        const { action, params } = await req.json();
        console.log(`Received action: ${action}`);

        switch (action) {
            case 'exchangeCodeForTokens':
                try {
                    const { userId, spapi_oauth_code, selling_partner_id, redirect_uri } = params;
                    // Note: The outline removed explicit validation here, relying on downstream errors if params are missing.
                    
                    console.log(`Exchanging code for user ID: ${userId}`);

                    const tokens = await exchangeCodeForTokens(spapi_oauth_code, redirect_uri);
                    const expiresAt = new Date(Date.now() + (tokens.expires_in * 1000));
                    
                    const connectionData = {
                        user_id: userId,
                        region: 'NA', // Default, could be made configurable
                        spapi_oauth_code, // Added as per outline
                        selling_partner_id,
                        access_token: tokens.access_token,
                        refresh_token: tokens.refresh_token,
                        token_expires_at: expiresAt.toISOString(),
                        status: 'active'
                    };
                    
                    await api.createEntityRecord('UserConnection', connectionData);
                    return new Response(JSON.stringify({ success: true, message: 'Connection created successfully' }), { headers: corsHeaders });
                } catch (error) {
                    console.error('Exchange code error:', error);
                    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
                }

            case 'syncUserOrders':
                try {
                    const { userId } = params;
                    if (!userId) {
                        return new Response(JSON.stringify({ error: 'userId parameter is required' }), { 
                            status: 400, 
                            headers: corsHeaders 
                        });
                    }
                    
                    console.log(`Syncing orders for user ID: ${userId}`);

                    // Get all connections and filter in-memory
                    const allConnections = await api.getEntityRecords('UserConnection');
                    const connections = allConnections.filter(c => c.user_id === userId && c.status === 'active');

                    if (connections.length === 0) {
                        return new Response(JSON.stringify({ 
                            error: 'No active Amazon connections found for user', // Changed to error message
                            totalFound: 0,
                            totalSynced: 0,
                            totalUpdated: 0,
                            connectionsProcessed: 0
                        }), { status: 404, headers: corsHeaders }); // Changed status to 404
                    }
                    
                    let totalFound = 0, totalSynced = 0, totalUpdated = 0;
                    
                    for (const connection of connections) {
                        const result = await syncUserOrdersInternal(api, userId, connection);
                        totalFound += result.totalFound;
                        totalSynced += result.totalSynced;
                        totalUpdated += result.totalUpdated;
                    }
                    
                    return new Response(JSON.stringify({ 
                        success: true,
                        totalFound,
                        totalSynced,
                        totalUpdated,
                        connectionsProcessed: connections.length
                    }), { headers: corsHeaders });
                    
                } catch (error) {
                    console.error('Sync orders error:', error);
                    return new Response(JSON.stringify({ 
                        error: error.message 
                    }), { status: 500, headers: corsHeaders });
                }

            case 'syncAllOrders':
                try {
                    // Get all connections and filter active ones in-memory
                    const allConnectionsRaw = await api.getEntityRecords('UserConnection');
                    const allActiveConnections = allConnectionsRaw.filter(c => c.status === 'active');
                    
                    // Group by user_id
                    const userConnections = {};
                    for (const conn of allActiveConnections) {
                        if (!userConnections[conn.user_id]) {
                            userConnections[conn.user_id] = [];
                        }
                        userConnections[conn.user_id].push(conn);
                    }
                    
                    let processedUsers = 0; // Distinct users for whom sync was attempted
                    let totalFound = 0, totalSynced = 0, totalUpdated = 0;
                    
                    if (Object.keys(userConnections).length === 0) {
                        return new Response(JSON.stringify({ 
                            success: true, 
                            message: "No active connections to sync.",
                            totalUsers: 0,
                            processedUsers: 0,
                            totalFound: 0,
                            totalSynced: 0,
                            totalUpdated: 0
                        }), { headers: corsHeaders });
                    }
                    
                    for (const [userId, connectionsForUser] of Object.entries(userConnections)) {
                        try {
                            console.log(`Processing user ID: ${userId} with ${connectionsForUser.length} connections`);
                            
                            for (const connection of connectionsForUser) {
                                const result = await syncUserOrdersInternal(api, userId, connection);
                                totalFound += result.totalFound;
                                totalSynced += result.totalSynced;
                                totalUpdated += result.totalUpdated;
                            }
                            
                            processedUsers++;
                        } catch (error) {
                            console.error(`Failed to sync user ID ${userId}:`, error.message);
                        }
                    }
                    
                    return new Response(JSON.stringify({ 
                        success: true,
                        totalUsers: Object.keys(userConnections).length, // total number of distinct users found with active connections
                        processedUsers: processedUsers, // number of distinct users actually processed
                        totalFound,
                        totalSynced,
                        totalUpdated
                    }), { headers: corsHeaders });
                    
                } catch (error) {
                    console.error('Sync all orders error:', error);
                    return new Response(JSON.stringify({ 
                        error: error.message 
                    }), { status: 500, headers: corsHeaders });
                }

            default:
                return new Response(JSON.stringify({ 
                    error: 'Unknown action',
                    availableActions: ['exchangeCodeForTokens', 'syncUserOrders', 'syncAllOrders']
                }), { status: 400, headers: corsHeaders });
        }

    } catch (error) {
        console.error('Main function error:', error);
        return new Response(JSON.stringify({ 
            error: 'Internal server error', 
            message: error.message 
        }), { status: 500, headers: corsHeaders });
    }
});
