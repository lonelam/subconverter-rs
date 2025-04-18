import type { VercelRequest, VercelResponse } from '@vercel/node';
import { initWasm } from '../../lib/enhanced-wasm-loader.js';

// --- WASM Setup ---
// This assumes your built WASM and the JS bindings are in a `pkg` directory
// relative to the Vercel function's root after deployment.
// You'll need to adjust the path based on your actual build process.
let wasmModule: any = null; // We'll use any to avoid type issues with new functions
let initPromise: Promise<any> | null = null;

// Import the WasmInitResult type if available, otherwise define it
type WasmInitResult = {
    success: boolean;
    module?: any;
    error?: any;
};

async function loadWasm() {
    if (!initPromise) {
        console.log("Initializing WASM using enhanced loader...");

        initPromise = initWasm()
            .then((result: WasmInitResult) => {
                if (result.success && result.module) {
                    wasmModule = result.module;
                    console.log("WASM initialized successfully.");
                    return wasmModule;
                } else {
                    throw result.error || new Error("WASM initialization failed");
                }
            })
            .catch((err: any) => {
                console.error("Failed to load or initialize WASM:", err);
                initPromise = null; // Reset promise on failure
                throw err; // Re-throw for handlers
            });
    }
    return initPromise;
}

export default async function handler(
    request: VercelRequest,
    response: VercelResponse,
) {
    try {
        await loadWasm(); // Ensure WASM is loaded and initialized
    } catch (error) {
        console.error("Failed to load WASM module:", error);
        return response.status(500).json({
            error: 'Failed to load WASM module',
            details: error instanceof Error ? error.message : String(error)
        });
    }

    // Extract the file path from the dynamic route parameter
    const pathParam = request.query.path;
    const filePath = Array.isArray(pathParam) ? pathParam.join('/') : pathParam;

    if (!filePath) {
        return response.status(400).json({ error: 'File path is required' });
    }

    console.log(`Admin API request: ${request.method} /admin/${filePath}`);

    try {
        switch (request.method) {
            case 'GET': { // Read file or check existence
                const checkExists = request.query.exists === 'true';
                const getAttributes = request.query.attributes === 'true';

                if (checkExists) {
                    const exists = await wasmModule.admin_file_exists(filePath);
                    console.log(`Exists check for ${filePath}: ${exists}`);
                    return response.status(200).json({ path: filePath, exists });
                } else if (getAttributes) {
                    // Get file attributes via the VFS
                    const attributes = await wasmModule.admin_get_file_attributes(filePath);
                    console.log(`Got attributes for ${filePath}:`, attributes);
                    return response.status(200).json({
                        path: filePath,
                        attributes
                    });
                } else {
                    const textContent = await wasmModule.admin_read_file(filePath);
                    // 直接返回文本内容，不再使用base64
                    console.log(`Read file ${filePath}, got text: ${textContent.substring(0, 50)}...`);
                    return response.status(200).json({ path: filePath, content: textContent });
                }
            }

            case 'POST': // Write file
            case 'PUT': { // Treat PUT same as POST for simplicity
                const { content: textContent, is_directory } = request.body;

                if (is_directory) {
                    // Creating a directory
                    console.log(`Creating directory ${filePath}`);
                    await wasmModule.admin_create_directory(filePath);
                    return response.status(200).json({
                        success: true,
                        path: filePath,
                        action: 'directory_created'
                    });
                } else if (typeof textContent !== 'string') {
                    return response.status(400).json({
                        error: 'Request body must contain a \'content\' field as string'
                    });
                } else {
                    // 直接写入文本内容，不再使用base64
                    console.log(`Write file ${filePath}, content: ${textContent.substring(0, 50)}...`);
                    await wasmModule.admin_write_file(filePath, textContent);
                    return response.status(200).json({
                        success: true,
                        path: filePath,
                        action: 'written'
                    });
                }
            }

            case 'DELETE': { // Delete file
                console.log(`Delete file ${filePath}`);
                await wasmModule.admin_delete_file(filePath);
                return response.status(200).json({ success: true, path: filePath, action: 'deleted' });
            }

            default:
                response.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
                return response.status(405).end(`Method ${request.method} Not Allowed`);
        }
    } catch (error: any) {
        console.error(`Error processing admin request for ${filePath}:`, error);
        // Try to extract a meaningful error message from the WASM error (often just a string)
        const errorMessage = typeof error === 'string' ? error : (error.message || 'Unknown WASM error');
        // Check for specific VFS errors if possible (depends on how you format vfs_error_to_js)
        if (errorMessage.includes('Not found')) {
            return response.status(404).json({ error: `File not found: ${filePath}`, details: errorMessage });
        } else if (errorMessage.includes('VFS Error')) {
            return response.status(500).json({ error: `VFS operation failed for ${filePath}`, details: errorMessage });
        } else {
            return response.status(500).json({ error: `Internal server error processing ${filePath}`, details: errorMessage });
        }
    }
} 