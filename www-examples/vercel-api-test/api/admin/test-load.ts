import type { VercelRequest, VercelResponse } from '@vercel/node';
import { initWasm } from '../../lib/enhanced-wasm-loader.js';

/**
 * Test API endpoint to trigger loading from GitHub and then list all files
 */
export default async function handler(
    request: VercelRequest,
    response: VercelResponse,
) {
    try {
        const path = request.query.path as string || '';
        // Default to shallow loading (true) unless explicitly set to false
        const shallow = request.query.shallow !== 'false';

        console.log(`Starting test load process for path: ${path} (shallow: ${shallow})`);

        // Attempt to load WASM module
        let wasmModule;
        try {
            console.log("Loading WASM module...");
            const result = await initWasm();
            if (!result.success) {
                throw new Error(`WASM initialization failed: ${result.error}`);
            }
            wasmModule = result.module;
            console.log("WASM loaded successfully");
        } catch (wasmError) {
            console.error("WASM failed to load:", wasmError);
            return response.status(500).json({
                success: false,
                error: `WASM failed to load: ${wasmError}`
            });
        }

        // First load from GitHub
        console.log(`Loading directory from GitHub: "${path}" (shallow: ${shallow})`);
        try {
            const loadResult = await wasmModule.admin_load_github_directory(path, shallow);
            console.log(`GitHub load result:`, loadResult);

            // Now list the directory
            console.log(`Listing directory: "${path}"`);
            const entries = await wasmModule.list_directory(path);
            console.log(`Directory listing result:`, entries);

            return response.status(200).json({
                success: true,
                path,
                shallow,
                loadResult,
                entries
            });
        } catch (error) {
            console.error(`Error during load/list operation:`, error);
            return response.status(500).json({
                success: false,
                error: `Operation failed: ${error}`
            });
        }
    } catch (error: any) {
        console.error('Error in test-load handler:', error);
        return response.status(500).json({
            success: false,
            error: `General error: ${error.message || error}`
        });
    }
} 