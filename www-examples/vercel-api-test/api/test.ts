import { kv } from '@vercel/kv';
import type { VercelRequest, VercelResponse } from '@vercel/node';

// WASM setup for testing
let wasmModule: any = null;

async function loadWasm() {
    try {
        console.log("Loading WASM module via dynamic import...");

        // Import the npm package installed from ../pkg
        const module = await import('subconverter-wasm');
        wasmModule = module;

        console.log("WASM module loaded, initializing...");
        await wasmModule.default();
        console.log("WASM initialized successfully.");

        return { success: true, message: "WASM loaded successfully" };
    } catch (err) {
        console.error("Failed to load or initialize WASM:", err);
        return {
            success: false,
            error: err instanceof Error ? err.message : String(err)
        };
    }
}

export default async function handler(
    request: VercelRequest,
    response: VercelResponse,
) {
    if (request.method === 'GET') {
        // Check if query has wasm=true parameter
        const checkWasm = request.query.wasm === 'true';

        if (checkWasm) {
            try {
                const wasmStatus = await loadWasm();

                // Try to call a WASM function if loaded
                let wasmFunctionResult = null;
                if (wasmStatus.success && wasmModule) {
                    try {
                        // Check if admin_file_exists is available
                        if (typeof wasmModule.admin_file_exists === 'function') {
                            wasmFunctionResult = {
                                tested: true,
                                function: 'admin_file_exists',
                                result: await wasmModule.admin_file_exists('README.md')
                            };
                        }
                    } catch (fnError) {
                        wasmFunctionResult = {
                            tested: true,
                            error: String(fnError)
                        };
                    }
                }

                return response.status(200).json({
                    test: 'wasm',
                    status: wasmStatus,
                    wasmFunction: wasmFunctionResult,
                    time: new Date().toISOString()
                });
            } catch (error) {
                return response.status(500).json({
                    test: 'wasm',
                    error: String(error),
                    time: new Date().toISOString()
                });
            }
        }

        // Regular KV test
        const key = request.query.key as string || 'defaultKey';
        try {
            const value = await kv.get(key);
            return response.status(200).json({
                test: 'kv',
                key,
                value,
                time: new Date().toISOString()
            });
        } catch (error) {
            console.error('Error getting value from KV:', error);
            return response.status(500).json({
                test: 'kv',
                error: 'Failed to get value from KV',
                details: String(error),
                time: new Date().toISOString()
            });
        }
    } else if (request.method === 'POST') {
        // Example: Set a value
        const { key, value } = request.body;
        if (!key || value === undefined) {
            return response.status(400).json({ error: 'Missing key or value in request body' });
        }
        try {
            await kv.set(key, value);
            return response.status(200).json({ success: true, key, value });
        } catch (error) {
            console.error('Error setting value in KV:', error);
            return response.status(500).json({ error: 'Failed to set value in KV' });
        }
    } else if (request.method === 'DELETE') {
        // Example: Delete a value
        const key = request.query.key as string;
        if (!key) {
            return response.status(400).json({ error: 'Missing key in query parameters' });
        }
        try {
            const result = await kv.del(key);
            return response.status(200).json({ success: result > 0, key, deletedCount: result });
        } catch (error) {
            console.error('Error deleting value from KV:', error);
            return response.status(500).json({ error: 'Failed to delete value from KV' });
        }
    }

    // Handle unsupported methods
    response.setHeader('Allow', ['GET', 'POST', 'DELETE']);
    return response.status(405).end(`Method ${request.method} Not Allowed`);
} 