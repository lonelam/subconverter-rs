import { initWasm } from '../../lib/enhanced-wasm-loader.js';

// Define a simple request interface that works for both environments
interface RequestLike {
    method?: string;
    json: () => Promise<any>;
}

/**
 * Load all files from a GitHub repository directory at once
 * 
 * This is an Edge API route handler that calls the Rust admin_load_github_directory function.
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

        // Parse the request body
        const body = await req.json();
        const path = body.path || '';
        const shallow = body.shallow !== false; // Default to true if not explicitly set to false

        // Check for empty path
        if (!path && path !== '') {
            return new Response(
                JSON.stringify({ error: 'Path is required' }),
                {
                    status: 400,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        console.log(`Starting WASM initialization for GitHub directory load: ${path} (shallow: ${shallow})`);

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

        // Call the Rust function with detailed error handling
        console.log(`Loading GitHub directory: ${path}`);

        try {
            const wasmInstance = result.module;
            console.log(`WASM instance loaded successfully. Calling admin_load_github_directory with path: ${path}, shallow: ${shallow}`);

            // Add this check to verify that the function exists
            if (typeof wasmInstance.admin_load_github_directory !== 'function') {
                console.error('Function admin_load_github_directory is not available in the WASM module');
                return new Response(
                    JSON.stringify({ error: 'Function admin_load_github_directory not found in WASM module' }),
                    {
                        status: 500,
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    }
                );
            }

            const loadResult = await wasmInstance.admin_load_github_directory(path, shallow);
            console.log('GitHub directory load completed successfully');

            // Return the result
            return new Response(
                JSON.stringify(loadResult),
                {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        } catch (wasmError) {
            // Detailed error logging for WASM execution errors
            console.error('WASM execution error:', wasmError);
            console.error('Error type:', Object.prototype.toString.call(wasmError));
            console.error('Error properties:', Object.getOwnPropertyNames(wasmError));

            if (wasmError instanceof Error) {
                console.error('Stack trace:', wasmError.stack);
            }

            return new Response(
                JSON.stringify({
                    error: 'WASM execution error',
                    message: String(wasmError),
                    type: Object.prototype.toString.call(wasmError),
                    properties: Object.getOwnPropertyNames(wasmError)
                }),
                {
                    status: 500,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
        }
    } catch (error) {
        // Detailed error logging for general errors
        console.error('Error in GitHub load handler:', error);
        console.error('Error type:', Object.prototype.toString.call(error));

        if (error instanceof Error) {
            console.error('Stack trace:', error.stack);
        }

        return new Response(
            JSON.stringify({
                error: 'Error in GitHub load handler',
                message: String(error),
                type: Object.prototype.toString.call(error),
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