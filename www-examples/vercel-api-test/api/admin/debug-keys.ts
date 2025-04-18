import type { VercelRequest, VercelResponse } from '@vercel/node';

// Import localStorageMap from the kv_bindings file
// This is a hack to expose the internal Map for debugging
let localStorageMap: Map<string, any>;
try {
    // Try to import from the root js directory first
    const module = require('../../../js/kv_bindings.js');
    localStorageMap = module.localStorageMap as Map<string, any>;
    console.log("Successfully imported localStorageMap from kv_bindings.js (root path)");
    console.log(`Current map has ${localStorageMap ? localStorageMap.size : 0} entries`);
} catch (error) {
    try {
        // Try alternate location in case the first fails
        const module = require('../../js/kv_bindings.js');
        localStorageMap = module.localStorageMap as Map<string, any>;
        console.log("Successfully imported localStorageMap from kv_bindings.js (alternate path)");
        console.log(`Current map has ${localStorageMap ? localStorageMap.size : 0} entries`);
    } catch (alternateError) {
        console.error("Failed to import localStorageMap from primary path:", error);
        console.error("Failed to import localStorageMap from alternate path:", alternateError);
        // Initialize with empty map to avoid undefined errors
        localStorageMap = new Map<string, any>();
    }
}

/**
 * Debug API endpoint to show all keys in the KV storage
 */
export default async function handler(
    request: VercelRequest,
    response: VercelResponse,
) {
    try {
        // If we couldn't import the map directly, fallback to an empty map
        const map = localStorageMap || new Map<string, any>();
        console.log(`Processing map with ${map.size} entries for debug endpoint`);

        // Convert to an array of entries for easier inspection
        const entries = Array.from(map.entries()).map(([key, value]: [string, any]) => {
            // For binary data, just show the type and length
            let safeValue: string;
            if (value instanceof Uint8Array) {
                safeValue = `Uint8Array(${value.length} bytes)`;
            } else if (typeof value === 'string') {
                safeValue = value.length > 100 ?
                    `${value.substring(0, 100)}... (${value.length} chars)` : value;
            } else if (value && typeof value === 'object') {
                safeValue = `Object with keys: ${Object.keys(value).join(', ')}`;
            } else {
                safeValue = String(value);
            }

            return {
                key,
                value: safeValue,
                type: value ? value.constructor.name : 'null',
                length: value instanceof Uint8Array ? value.length :
                    typeof value === 'string' ? value.length :
                        null
            };
        });

        return response.status(200).json({
            success: true,
            count: entries.length,
            keys: entries.map((e: { key: string }) => e.key),
            entries
        });
    } catch (error: any) {
        console.error('Error getting KV debug info:', error);
        return response.status(500).json({
            error: 'Failed to get KV debug info',
            details: error.message || 'Unknown error'
        });
    }
} 