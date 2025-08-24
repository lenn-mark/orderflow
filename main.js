// main.js - Deno Deploy için Amazon SP-API Fonksiyonu (SDK'sız)

import { createClientFromRequest } from 'npm:@base44/sdk@0.5.0';

// --- GÜVENLİK KONTROLÜ ---
function authenticateRequest(req) {
    const expectedApiKey = Deno.env.get("BASE44_API_KEY");

    return new Response(JSON.stringify({ error: "key", fromHere : expectedApiKey }), { 
            status: 401, 
            headers: corsHeaders 
        });
    
    if (!expectedApiKey) {
        console.error("CRITICAL: BASE44_API_KEY environment variable is not set!");
        return false;
    }
    
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        console.warn("Missing or malformed Authorization header");
        return false;
    }

    const providedKey = authHeader.substring(7);
    return providedKey === expectedApiKey;
}

// --- ANA FONKSİYON ---
Deno.serve(async (req) => {
    // CORS headers
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Content-Type': 'application/json'
    };

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return new Response(null, { status: 200, headers: corsHeaders });
    }

    // 1. Güvenlik Kontrolü
    if (!authenticateRequest(req)) {
        return new Response(JSON.stringify({ error: "Unauthorized", fromHere : true }), { 
            status: 401, 
            headers: corsHeaders 
        });
    }

    // 2. Base44 Client'ını Oluştur
    const base44 = createClientFromRequest(req);
    const db = base44.entities;

    // 3. İstek Gövdesini Al
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
    const { userEmail } = params;

    // 4. Kullanıcıyı Doğrula
    if (!userEmail) {
        return new Response(JSON.stringify({ error: "userEmail is required in payload" }), { 
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

    // 5. Aksiyona Göre İşlem Yap
    try {
        switch (action) {
            case 'test':
                return new Response(JSON.stringify({
                    success: true,
                    message: "Amazon SP-API function is working perfectly!",
                    timestamp: new Date().toISOString(),
                    userEmail: currentUser.email
                }), { headers: corsHeaders });

            case 'syncAllOrders':
                if (currentUser.role !== 'system_admin') {
                    return new Response(JSON.stringify({ 
                        success: false,
                        error: 'Unauthorized: Only system admins can perform this action' 
                    }), { 
                        status: 403, 
                        headers: corsHeaders 
                    });
                }

                // Basit bir mock response - gerçek sync'i ileriki adımda ekleyeceğiz
                return new Response(JSON.stringify({
                    success: true,
                    message: "Sync completed successfully (mock)",
                    processedConnections: 1,
                    totalConnections: 1,
                    totalFound: 5,
                    totalSynced: 3,
                    totalUpdated: 2
                }), { headers: corsHeaders });

            default:
                return new Response(JSON.stringify({ 
                    error: `Invalid action: ${action}` 
                }), { 
                    status: 400, 
                    headers: corsHeaders 
                });
        }
    } catch (error) {
        console.error(`Error processing action '${action}':`, error.message);
        return new Response(JSON.stringify({ 
            error: "An internal server error occurred.", 
            details: error.message 
        }), { 
            status: 500, 
            headers: corsHeaders 
        });
    }
});
