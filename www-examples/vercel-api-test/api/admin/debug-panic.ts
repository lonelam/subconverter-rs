import { initWasm } from '../../lib/enhanced-wasm-loader.js';

// Define a simple request interface
interface RequestLike {
    method?: string;
}

/**
 * Debug endpoint to test WebAssembly panic handling and stack traces
 */
export default async function handler(req: RequestLike) {
    try {
        // Only allow POST requests
        if (req.method !== 'POST') {
            return new Response(
                JSON.stringify({ error: 'Method not allowed' }),
                {
                    status: 405,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        console.log('Starting WASM initialization for panic test...');

        // Initialize the Wasm module
        const result = await initWasm();

        if (!result.success || !result.module) {
            console.error('WASM initialization failed:', result.error);
            return new Response(
                JSON.stringify({ error: 'Failed to initialize WASM module', details: String(result.error) }),
                {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        // Call the test panic function
        try {
            const wasmInstance = result.module;
            console.log('WASM instance loaded successfully. Calling panic test function...');

            // Verify function exists
            if (typeof wasmInstance.admin_debug_test_panic !== 'function') {
                return new Response(
                    JSON.stringify({ error: 'Function admin_debug_test_panic not found in WASM module' }),
                    {
                        status: 500,
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    }
                );
            }

            // This should trigger a panic
            wasmInstance.admin_debug_test_panic();

            // If we get here, something went wrong with our panic test
            return new Response(
                JSON.stringify({ error: 'Panic test did not trigger a panic as expected' }),
                {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        } catch (panicError) {
            // This is expected - detailed logging for the panic
            console.error('Panic captured successfully:', panicError);
            console.error('Error type:', Object.prototype.toString.call(panicError));
            console.error('Error properties:', Object.getOwnPropertyNames(panicError));

            if (panicError instanceof Error) {
                console.error('Stack trace:', panicError.stack);
            }

            return new Response(
                JSON.stringify({
                    success: true,
                    message: 'Panic test executed successfully',
                    error: String(panicError),
                    type: Object.prototype.toString.call(panicError),
                    properties: Object.getOwnPropertyNames(panicError),
                    stack: panicError instanceof Error ? panicError.stack : undefined
                }),
                {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        }
    } catch (error) {
        // Unexpected error
        console.error('Unexpected error in panic test:', error);

        if (error instanceof Error) {
            console.error('Stack trace:', error.stack);
        }

        return new Response(
            JSON.stringify({
                error: 'Unexpected error in panic test',
                message: String(error),
                stack: error instanceof Error ? error.stack : undefined
            }),
            {
                status: 500,
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        );
    }
} 