/**
 * Enhanced WASM loading helper for Next.js API routes
 */

import fs from 'fs';
import path from 'path';

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
    path.resolve(process.cwd(), 'node_modules', 'subconverter-wasm', 'subconverter_bg.wasm'),
];

/**
 * Attempt to load the WASM file from any of the possible locations
 */
export function findWasmFile() {
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
 * Print available modules and functions in a WASM module
 */
function inspectWasmModule(module) {
    console.log('Inspecting WASM module content:');
    console.log('- Module type:', typeof module);

    if (typeof module !== 'object' || module === null) {
        console.log('- Module is not an object');
        return;
    }

    const properties = Object.getOwnPropertyNames(module).sort();
    console.log(`- Module has ${properties.length} properties:`);

    for (const prop of properties) {
        try {
            const value = module[prop];
            const type = typeof value;
            const isFunction = type === 'function';
            console.log(`  - ${prop}: ${type}${isFunction ? ' (function)' : ''}`);
        } catch (e) {
            console.log(`  - ${prop}: [Error accessing: ${e.message}]`);
        }
    }

    // Look specifically for the functions we need
    const criticalFunctions = [
        'admin_load_github_directory',
        'admin_read_file',
        'admin_write_file',
        'admin_delete_file',
        'admin_file_exists',
        'admin_get_file_attributes',
        'admin_create_directory',
        'list_directory'
    ];

    console.log('- Checking critical functions:');
    for (const funcName of criticalFunctions) {
        const exists = typeof module[funcName] === 'function';
        console.log(`  - ${funcName}: ${exists ? '✅ Available' : '❌ Missing'}`);
    }
}

/**
 * Initialize the WASM module with proper error handling
 */
export async function initWasm() {
    try {
        console.log('🔄 Trying to load WASM module...');

        // First try standard import
        let wasmModule;
        try {
            wasmModule = await import('subconverter-wasm');
            console.log('WASM module loaded successfully via import.');
        } catch (importError) {
            console.error('Error loading WASM via import:', importError);
            console.error('Trying alternative loading method...');

            // Try more direct approach if normal import fails
            try {
                // This is a fallback for environments where dynamic imports might not work as expected
                wasmModule = require('subconverter-wasm');
                console.log('WASM module loaded successfully via require.');
            } catch (requireError) {
                console.error('Error loading WASM via require:', requireError);
                throw new Error(`Failed to load WASM module: ${importError.message} / ${requireError.message}`);
            }
        }

        // Validate that we got something useful
        if (!wasmModule) {
            throw new Error('WASM module is undefined after loading');
        }

        // Initialize WASM logging and panic hook
        try {
            if (typeof wasmModule.init_wasm_logging === 'function') {
                console.log('Initializing WASM logging with panic hook...');
                wasmModule.init_wasm_logging('debug');
                console.log('WASM logging initialized successfully');
            } else if (typeof wasmModule.init_panic_hook === 'function') {
                console.log('Initializing WASM panic hook...');
                wasmModule.init_panic_hook();
                console.log('WASM panic hook initialized successfully');
            } else {
                console.warn('WASM logging/panic initialization functions not found');
            }
        } catch (logError) {
            console.error('Error initializing WASM logging/panic hook:', logError);
            // Continue anyway - the module might still work
        }

        // Inspect module content to help diagnose issues
        inspectWasmModule(wasmModule);

        return {
            success: true,
            module: wasmModule
        };
    } catch (error) {
        console.error('❌ Error loading WASM module:', error);
        console.error('Stack trace:', error.stack);

        return {
            success: false,
            error: error instanceof Error ? error : new Error(String(error))
        };
    }
} 