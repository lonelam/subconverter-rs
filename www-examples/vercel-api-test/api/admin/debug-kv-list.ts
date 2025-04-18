import type { VercelRequest, VercelResponse } from '@vercel/node';
import { initWasm } from '../../lib/enhanced-wasm-loader.js';

// Direct access to KV bindings for testing
let kvBindings: any;
try {
    // Try to import from the root js directory first
    const module = require('../../../js/kv_bindings.js');
    kvBindings = module;
    console.log("Successfully imported KV bindings module from root");
} catch (error) {
    try {
        // Try alternate location in case the first fails
        const module = require('../../js/kv_bindings.js');
        kvBindings = module;
        console.log("Successfully imported KV bindings module from alternate path");
    } catch (alternateError) {
        console.error("Failed to import KV bindings from primary path:", error);
        console.error("Failed to import KV bindings from alternate path:", alternateError);
        kvBindings = null;
    }
}

/**
 * Debug API endpoint to test KV list functionality
 * This endpoint provides direct access to KV list operations and allows testing
 * the behavior of both the JS binding and the Rust implementation
 */
export default async function handler(
    request: VercelRequest,
    response: VercelResponse,
) {
    try {
        // Get prefix from query or body
        const prefix = request.query.prefix as string ||
            (request.body && request.body.prefix) ||
            '';

        // Default shallow to true unless explicitly set to false
        const shallow = request.query.shallow !== 'false';

        console.log(`Debug KV list with prefix: '${prefix}' (shallow: ${shallow})`);

        // Initialize WASM module for the Rust-side test
        const wasmResult = await initWasm();

        // First, test the JS binding directly
        let jsListResult: any[] = [];
        let jsListError = null;

        try {
            if (kvBindings && typeof kvBindings.kv_list === 'function') {
                console.log(`Testing JS kv_list binding with prefix: '${prefix}'`);
                jsListResult = await kvBindings.kv_list(prefix);
                console.log(`JS kv_list returned ${jsListResult.length} keys`);
            } else {
                jsListError = "KV bindings not available or kv_list function not found";
            }
        } catch (error) {
            console.error(`Error calling JS kv_list:`, error);
            jsListError = String(error);
        }

        // Next, test the Rust implementation if WASM loaded
        let rustListResult: any = null;
        let rustListError = null;

        if (wasmResult.success && wasmResult.module) {
            try {
                console.log(`Testing Rust debug_list_directory with path: '${prefix}' (shallow: ${shallow})`);

                // Check if the debug function exists
                if (typeof wasmResult.module.debug_list_directory === 'function') {
                    rustListResult = await wasmResult.module.debug_list_directory(prefix, shallow);
                    console.log(`Rust debug_list_directory completed successfully`);
                } else if (typeof wasmResult.module.list_directory === 'function') {
                    // Fallback to standard list_directory
                    rustListResult = await wasmResult.module.list_directory(prefix);
                    console.log(`Rust list_directory completed successfully`);
                } else {
                    rustListError = "Debug or list directory functions not found in WASM module";
                }
            } catch (error) {
                console.error(`Error calling Rust list directory function:`, error);
                rustListError = String(error);
            }
        } else {
            rustListError = wasmResult.error || "Failed to initialize WASM module";
        }

        // Let's also check if the directory exists according to Rust
        let directoryExists = false;
        let existsError = null;

        if (wasmResult.success && wasmResult.module && typeof wasmResult.module.exists === 'function') {
            try {
                directoryExists = await wasmResult.module.exists(prefix);
                console.log(`Directory '${prefix}' exists check result: ${directoryExists}`);
            } catch (error) {
                console.error(`Error checking if directory exists:`, error);
                existsError = String(error);
            }
        }

        // Now let's try raw KV operations directly
        let kvRawListResult: any[] = [];
        let kvRawListError = null;

        try {
            if (kvBindings) {
                // This tests the underlying KV scan functionality
                const rawScanResult = await kvBindings.getKv().then((kv: any) => kv.scan(0, { match: `${prefix}*`, count: 100 }));
                kvRawListResult = rawScanResult[1] || [];
                console.log(`Raw KV scan returned ${kvRawListResult.length} keys`);
            }
        } catch (error) {
            console.error(`Error with raw KV scan:`, error);
            kvRawListError = String(error);
        }

        // Return comprehensive debug results
        return response.status(200).json({
            success: true,
            prefix,
            shallow,
            js_binding: {
                success: !jsListError,
                error: jsListError,
                keys: jsListResult,
                count: jsListResult.length
            },
            rust_implementation: {
                success: !rustListError,
                error: rustListError,
                result: rustListResult
            },
            directory_exists: {
                success: !existsError,
                error: existsError,
                exists: directoryExists
            },
            kv_raw_scan: {
                success: !kvRawListError,
                error: kvRawListError,
                keys: kvRawListResult,
                count: kvRawListResult.length
            }
        });
    } catch (error: any) {
        console.error('Error in debug-kv-list handler:', error);
        return response.status(500).json({
            error: 'Failed to execute KV list debug',
            details: error.message || 'Unknown error'
        });
    }
} 