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
            // Deno Deploy'daki environment variable'ları kullanarak SDK'yı başlatıyoruz.
            appId: Deno.env.get("BASE44_APP_ID"),
            apiKey: Deno.env.get("BASE44_API_KEY") // Bu, Service Role anahtarı olmalı
        });
        const db = base44.asServiceRole.entities; // Admin yetkileriyle işlem yapmak için asServiceRole kullanıyoruz

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

        if (action !== 'test' && !userEmail) {
            return new Response(JSON.stringify({ error: "userEmail is required in payload" }), { 
                status: 400, 
                headers: corsHeaders 
            });
        }

        switch (action) {
            case 'test':
                return new Response(JSON.stringify({
                    success: true,
                    message: "Deno function is working perfectly!",
                    timestamp: new Date().toISOString()
                }), { headers: corsHeaders });

            case 'syncAllOrders':
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
                        success: false,
                        error: 'Unauthorized: Only system admins can perform this action' 
                    }), { 
                        status: 403, 
                        headers: corsHeaders 
                    });
                }

                // TODO: Gerçek senkronizasyon mantığı buraya eklenecek.
                return new Response(JSON.stringify({
                    success: true,
                    message: "Sync completed successfully (mock response)",
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
        console.error(`Error processing request:`, error);
        return new Response(JSON.stringify({ 
            error: "An internal server error occurred in Deno Deploy function.", 
            details: error.message 
        }), { 
            status: 500, 
            headers: corsHeaders 
        });
    }
});
