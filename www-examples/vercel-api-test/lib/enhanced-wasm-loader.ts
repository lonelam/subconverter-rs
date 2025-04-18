/**
 * Enhanced WASM loading helper for Next.js API routes
 */

import fs from 'fs';
import path from 'path';

/**
 * Result of WASM initialization
 */
export interface WasmInitResult {
    success: boolean;
    module?: any;
    error?: Error;
}

// Array of potential relative paths to look for the WASM file
const possiblePaths = [
    // Default location when imported directly 
    '../pkg/subconverter_bg.wasm',
    // Location when running in .next/server
    './subconverter_bg.wasm',
    // Root of the project
    '../../pkg/subconverter_bg.wasm',
    // Absolute path based on current file
    path.resolve(process.cwd(), 'pkg', 'subconverter_bg.wasm'),
    // From node_modules
    path.resolve(process.cwd(), 'node_modules', 'subconverter', 'subconverter_bg.wasm'),
];

/**
 * Attempt to load the WASM file from any of the possible locations
 */
export function findWasmFile(): string | null {
    for (const relativePath of possiblePaths) {
        try {
            const absolutePath = path.isAbsolute(relativePath)
                ? relativePath
                : path.resolve(__dirname, relativePath);

            // Check if file exists
            if (fs.existsSync(absolutePath)) {
                console.log(`✅ Found WASM file at ${absolutePath}`);
                return absolutePath;
            }
        } catch (error) {
            // Ignore errors and try next path
        }
    }

    console.error('❌ Could not find WASM file in any of the possible locations');
    return null;
}

/**
 * Initialize the WASM module with proper error handling
 */
export async function initWasm(): Promise<WasmInitResult> {
    try {
        console.log('🔄 Trying to load WASM module...');

        // First try standard import
        const wasmModule = await import('subconverter-wasm');
        await wasmModule;

        return {
            success: true,
            module: wasmModule
        };
    } catch (error) {
        console.error('❌ Error loading WASM module:', error);
        return {
            success: false,
            error: error instanceof Error ? error : new Error(String(error))
        };
    }
} 