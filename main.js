// main.js - Deno Deploy için Amazon SP-API Fonksiyonu

import { createClientFromRequest } from 'npm:@base44/sdk@0.5.0';
import { SellingPartnerApiAuth } from 'npm:amazon-sp-api-sdk@3.1.0';

// --- GÜVENLİK KONTROLÜ ---
// Bu fonksiyon, isteğin bizim base44 uygulamamızdan geldiğini doğrular.
function authenticateRequest(req) {
    const expectedApiKey = Deno.env.get("BASE44_API_KEY");
    if (!expectedApiKey) {
        console.error("CRITICAL: BASE44_API_KEY environment variable is not set!");
        return false;
    }
    
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        console.warn("Missing or malformed Authorization header");
        return false;
    }

    const providedKey = authHeader.substring(7); // "Bearer " kısmını atla
    return providedKey === expectedApiKey;
}

// --- ANA FONKSİYON ---
Deno.serve(async (req) => {
    // 1. Güvenlik Kontrolü
    if (!authenticateRequest(req)) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    // 2. Base44 Client'ını Oluştur
    const base44 = createClientFromRequest(req);
    const db = base44.entities;

    // 3. İstek Gövdesini (Payload) Al
    let payload = {};
    try {
        payload = await req.json();
    } catch (e) {
        return new Response(JSON.stringify({ error: "Invalid JSON in request body" }), { status: 400 });
    }
    const { action, params = {} } = payload;
    const { userEmail } = params; // userEmail'i payload'dan alıyoruz.

    // 4. Kullanıcıyı Doğrula
    if (!userEmail) {
        return new Response(JSON.stringify({ error: "userEmail is required in payload" }), { status: 400 });
    }
    const user = await db.User.filter({ email: userEmail });
    if (!user || user.length === 0) {
        return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
    }
    const currentUser = user[0];

    // 5. Aksiyona Göre İşlem Yap
    try {
        switch (action) {
            case 'syncAllOrders':
                // Bu aksiyon sadece sistem yöneticileri tarafından tetiklenebilir
                if (currentUser.role !== 'system_admin') {
                    return new Response(JSON.stringify({ error: 'Unauthorized: Only system admins can perform this action' }), { status: 403 });
                }
                const allUsersWithConnections = await db.UserConnection.filter({ status: 'active' });
                const uniqueUserIds = [...new Set(allUsersWithConnections.map(c => c.user_id))];
                
                let totalProcessed = 0, totalFound = 0, totalSynced = 0, totalUpdated = 0;

                for (const userId of uniqueUserIds) {
                    const userConnections = allUsersWithConnections.filter(c => c.user_id === userId);
                    const userMarketplaces = await db.UserMarketplace.filter({ user_id: userId, is_active: true });
                    const marketplaceIds = userMarketplaces.map(m => m.marketplace_id);
                    
                    console.log(`Syncing for user ID: ${userId}, connections: ${userConnections.length}, marketplaces: ${marketplaceIds.length}`);

                    for (const connection of userConnections) {
                        const result = await syncOrdersForConnection(connection, marketplaceIds, db);
                        totalFound += result.totalFound;
                        totalSynced += result.totalSynced;
                        totalUpdated += result.totalUpdated;
                    }
                    totalProcessed++;
                }

                return new Response(JSON.stringify({
                    success: true,
                    processedConnections: totalProcessed,
                    totalConnections: uniqueUserIds.length,
                    totalFound, totalSynced, totalUpdated
                }));

            default:
                return new Response(JSON.stringify({ error: `Invalid action: ${action}` }), { status: 400 });
        }
    } catch (error) {
        console.error(`Error processing action '${action}':`, error.message, error.stack);
        return new Response(JSON.stringify({ error: "An internal server error occurred.", details: error.message }), { status: 500 });
    }
});


// --- YARDIMCI FONKSİYONLAR ---

async function getValidAccessToken(connection, db) {
    if (connection.access_token && new Date(connection.token_expires_at) > new Date()) {
        return connection.access_token;
    }
    const appContexts = await db.AmazonAppContext.filter({});
    if (!appContexts || appContexts.length === 0) throw new Error("Amazon application context not found.");
    
    const auth = new SellingPartnerApiAuth({
        clientId: appContexts[0].clientId,
        clientSecret: appContexts[0].clientSecret,
        refreshToken: connection.refresh_token,
    });
    const data = await auth.getAccessToken();
    if (!data.access_token) throw new Error('Could not retrieve access token');

    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + data.expires_in - 300);

    await db.UserConnection.update(connection.id, {
        access_token: data.access_token,
        token_expires_at: expiresAt.toISOString(),
    });
    return data.access_token;
}

async function makeSpApiRequest(path, params, connection, db, method = 'GET') {
    const accessToken = await getValidAccessToken(connection, db);
    const endpoint = `https://sellingpartnerapi-${connection.region.toLowerCase()}.amazon.com`;
    const url = new URL(path, endpoint);
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));

    const response = await fetch(url.toString(), {
        method,
        headers: { 'x-amz-access-token': accessToken }
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`SP-API Error (${response.status}): ${errorText}`);
    }
    return response.json();
}

async function syncOrdersForConnection(connection, marketplaceIds, db) {
    console.log(`Starting sync for connection: ${connection.id} in region: ${connection.region}`);
    let totalFound = 0, totalSynced = 0, totalUpdated = 0;
    
    try {
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        
        const params = {
            MarketplaceIds: marketplaceIds.join(','),
            CreatedAfter: thirtyDaysAgo.toISOString(),
            OrderStatuses: 'Unshipped,PartiallyShipped,Shipped,Pending,InvoiceUnconfirmed'
        };

        const data = await makeSpApiRequest('/orders/v0/orders', params, connection, db);
        const ordersFromApi = data.payload?.Orders || [];
        totalFound = ordersFromApi.length;
        console.log(`Found ${totalFound} orders from API for connection ${connection.id}`);

        if (totalFound > 0) {
            const amazonOrderIds = ordersFromApi.map(o => o.AmazonOrderId);
            const existingOrders = await db.Order.filter({ amazon_order_id: { $in: amazonOrderIds } });
            const existingOrdersMap = new Map(existingOrders.map(o => [o.amazon_order_id, o]));

            const toCreate = [];
            const toUpdate = [];

            for (const orderData of ordersFromApi) {
                const mappedOrder = {
                    amazon_order_id: orderData.AmazonOrderId,
                    seller_order_id: orderData.SellerOrderId,
                    purchase_date: orderData.PurchaseDate,
                    last_update_date: orderData.LastUpdateDate,
                    order_status: orderData.OrderStatus,
                    fulfillment_channel: orderData.FulfillmentChannel,
                    sales_channel: orderData.SalesChannel,
                    ship_service_level: orderData.ShipServiceLevel,
                    order_total: orderData.OrderTotal,
                    number_of_items_shipped: orderData.NumberOfItemsShipped,
                    number_of_items_unshipped: orderData.NumberOfItemsUnshipped,
                    payment_method: orderData.PaymentMethod,
                    marketplace_id: orderData.MarketplaceId,
                    is_business_order: orderData.IsBusinessOrder,
                    is_prime: orderData.IsPrime,
                    shipping_address: orderData.ShippingAddress,
                    buyer_info: orderData.BuyerInfo,
                    created_by: connection.created_by,
                };
                
                if (existingOrdersMap.has(orderData.AmazonOrderId)) {
                    toUpdate.push({ id: existingOrdersMap.get(orderData.AmazonOrderId).id, data: mappedOrder });
                } else {
                    toCreate.push(mappedOrder);
                }
            }

            if (toCreate.length > 0) await db.Order.bulkCreate(toCreate);
            for (const item of toUpdate) await db.Order.update(item.id, item.data);
            
            totalSynced = toCreate.length;
            totalUpdated = toUpdate.length;
        }
    } catch (error) {
        console.error(`Error syncing for connection ${connection.id}:`, error);
    }
    
    return { totalFound, totalSynced, totalUpdated };
}
