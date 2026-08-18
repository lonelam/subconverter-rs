import { FileAttributes } from 'subconverter-wasm';

/**
 * Response data from the subscription converter API
 */
export interface SubResponseData {
    content: string;
    content_type: string;
    headers: Record<string, string>;
    status_code: number;
}

/**
 * Error data returned from API calls
 */
export interface ErrorData {
    error: string;
    details?: string;
}

/**
 * Parameters for subscription conversion
 */
export interface SubconverterFormParams {
    target: string;
    flavor?: string;
    ver?: number;
    new_name?: boolean;
    url: string;
    group?: string;
    upload_path?: string;
    include?: string;
    exclude?: string;
    groups?: string;
    ruleset?: string;
    config?: string;
    dev_id?: string;
    insert?: boolean;
    prepend?: boolean;
    filename?: string;
    append_type?: boolean;
    emoji?: boolean;
    add_emoji?: boolean;
    remove_emoji?: boolean;
    list?: boolean;
    sort?: boolean;
    sort_script?: string;
    fdn?: boolean;
    rename?: string;
    tfo?: boolean;
    udp?: boolean;
    scv?: boolean;
    tls13?: boolean;
    rename_node?: boolean;
    interval?: number;
    strict?: boolean;
    upload?: boolean;
    token?: string;
    filter?: string;
    script?: boolean;
    classic?: boolean;
    expand?: boolean;
}

/**
 * Rules update request parameters
 */
export interface RulesUpdateRequest {
    config_path?: string;
}

/**
 * Rules update result interfaces
 */
export interface RulesUpdateResult {
    success: boolean;
    message: string;
    details: Record<string, RepoUpdateResult>;
}

export interface RepoUpdateResult {
    repo_name: string;
    files_updated: string[];
    errors: string[];
    status: string;
}

/**
 * Convert a subscription using the subconverter API
 */
export async function convertSubscription(formData: Partial<SubconverterFormParams>): Promise<SubResponseData> {
    const payload: Record<string, any> = {};

    // Create payload with only the explicitly set fields
    Object.keys(formData).forEach(key => {
        if (key in formData) {
            const value = (formData as any)[key];
            // Include the field if it exists in formData
            payload[key] = value;
        }
    });

    // Special handling for emoji flags
    if (payload.emoji === true) {
        // If combined emoji is true, remove the specific flags
        delete payload.add_emoji;
        delete payload.remove_emoji;
    }

    console.log("Sending conversion request with payload:", payload);

    const response = await fetch('/api/sub', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
    });

    const responseText = await response.text();

    if (!response.ok) {
        try {
            const errorObj = JSON.parse(responseText);
            throw errorObj;
        } catch (err) {
            if (typeof err === 'object' && err !== null && 'error' in err) {
                throw err;
            }
            throw {
                error: 'Error from server',
                details: responseText
            };
        }
    }

    const contentType = response.headers.get('Content-Type') || 'text/plain';

    const responseData: SubResponseData = {
        content: responseText,
        content_type: contentType,
        headers: {},
        status_code: response.status
    };

    response.headers.forEach((value, key) => {
        responseData.headers[key] = value;
    });

    return responseData;
}

/**
 * Update rules from configured GitHub repositories
 */
export async function updateRules(configPath?: string): Promise<RulesUpdateResult> {
    const response = await fetch('/api/admin/rules/update', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            config_path: configPath
        }),
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                success: false,
                message: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : { error: text }
            } as RulesUpdateResult;
        }
    }

    return response.json() as Promise<RulesUpdateResult>;
}

/**
 * Read file content from the server
 */
export async function readFile(path: string): Promise<string> {
    const response = await fetch(`/api/admin/${encodeURIComponent(path)}`);

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to read file: ${response.statusText}`);
    }

    const data = await response.json();
    return data.content || '';
}

/**
 * Write content to a file on the server
 */
export async function writeFile(path: string, content: string): Promise<void> {
    const response = await fetch(`/api/admin/${encodeURIComponent(path)}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ content }),
    });

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to write file: ${response.statusText}`);
    }
}

/**
 * Delete a file or directory on the server
 */
export async function deleteFile(path: string): Promise<void> {
    const response = await fetch(`/api/admin/${encodeURIComponent(path)}`, {
        method: 'DELETE',
    });

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to delete file: ${response.statusText}`);
    }
}

/**
 * Check if a file exists on the server
 */
export async function checkFileExists(path: string): Promise<boolean> {
    const response = await fetch(`/api/admin/${encodeURIComponent(path)}?exists=true`);

    if (!response.ok) {
        return false;
    }

    const data = await response.json();
    return data.exists || false;
}

/**
 * Get file attributes from the server
 */
export async function getFileAttributes(path: string): Promise<FileAttributes> {
    const response = await fetch(`/api/admin/${encodeURIComponent(path)}?attributes=true`);

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to get file attributes: ${response.statusText}`);
    }

    const data = await response.json();
    return data.attributes;
}

/**
 * Create a directory on the server
 */
export async function createDirectory(path: string): Promise<void> {
    const response = await fetch(`/api/admin/${encodeURIComponent(path)}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ is_directory: true }),
    });

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to create directory: ${response.statusText}`);
    }
}

/**
 * List files in a directory
 */
export async function listDirectory(path: string = ''): Promise<any> {
    const response = await fetch(`/api/admin/list?path=${encodeURIComponent(path)}`);

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to list directory: ${response.statusText}`);
    }

    return await response.json();
}

/**
 * Load files from a GitHub repository
 */
export async function loadGitHubDirectory(
    path: string,
    shallow: boolean = true,
    recursive: boolean = true
): Promise<any> {
    const response = await fetch(
        `/api/admin/github?path=${encodeURIComponent(path)}&shallow=${shallow}&recursive=${recursive}`
    );

    if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || `Failed to load GitHub directory: ${response.statusText}`);
    }

    const data = await response.json();
    return data.result;
}

/**
 * Format a file size number to a human-readable string
 */
export function formatFileSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/**
 * Format a timestamp (seconds since epoch) to a localized date string
 */
export function formatTimestamp(timestamp: number): string {
    return new Date(timestamp * 1000).toLocaleString();
}

/**
 * Short URL data structure
 */
export interface ShortUrlData {
    id: string;
    target_url: string;
    short_url: string;
    created_at: number;
    last_used?: number;
    use_count: number;
    custom_id: boolean;
    description?: string;
}

/**
 * Short URL creation request
 */
export interface CreateShortUrlRequest {
    target_url: string;
    custom_id?: string;
    description?: string;
}

/**
 * Create a new short URL
 */
export async function createShortUrl(request: CreateShortUrlRequest): Promise<ShortUrlData> {
    const response = await fetch('/api/s', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<ShortUrlData>;
}

/**
 * Get list of all short URLs
 */
export async function listShortUrls(): Promise<ShortUrlData[]> {
    const response = await fetch('/api/s');

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    const data = await response.json();
    return data.urls || [];
}

/**
 * Delete a short URL
 */
export async function deleteShortUrl(id: string): Promise<void> {
    const response = await fetch(`/api/s/${encodeURIComponent(id)}`, {
        method: 'DELETE',
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }
}

/**
 * Update a short URL
 */
export async function updateShortUrl(id: string, updates: { target_url?: string; description?: string | null; custom_id?: string }): Promise<ShortUrlData> {
    const response = await fetch(`/api/s/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(updates),
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<ShortUrlData>;
}

/**
 * Move a short URL to a new ID/alias
 */
export async function moveShortUrl(id: string, newId: string): Promise<ShortUrlData> {
    const response = await fetch(`/api/s/${encodeURIComponent(id)}/move`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ new_id: newId }),
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<ShortUrlData>;
}

/**
 * Interface for application download information
 */
export interface AppDownloadInfo {
    name: string;
    version: string;
    platform: string;
    size: number;
    download_url: string;
    release_date: string;
    description: string;
}

/**
 * Interface for platform configuration
 */
export interface PlatformConfig {
    repo: string;
    asset_pattern: string;
    fallback_url: string;
}

/**
 * Interface for app download configuration
 */
export interface AppDownloadConfig {
    name: string;
    description: string;
    platforms: Record<string, PlatformConfig>;
}

/**
 * Get available application downloads
 */
export async function getAvailableDownloads(): Promise<AppDownloadInfo[]> {
    const response = await fetch('/api/downloads');

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<AppDownloadInfo[]>;
}

/**
 * Download application
 * Returns a URL to initiate the download
 */
export function getDownloadUrl(appId: string, platform: string): string {
    return `/api/downloads/${encodeURIComponent(appId)}/${encodeURIComponent(platform)}`;
}

/**
 * Get the download configs from the admin API
 * This is only available to admin users
 */
export async function getDownloadConfigs(): Promise<AppDownloadConfig[]> {
    const response = await fetch('/api/admin/downloads');

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    const data = await response.json();
    return data.downloads || [];
}

/**
 * Update the download configs via the admin API
 * This is only available to admin users
 */
export async function updateDownloadConfigs(downloads: AppDownloadConfig[]): Promise<boolean> {
    const response = await fetch('/api/admin/downloads', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ downloads }),
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    const result = await response.json();
    return result.success === true;
}

/**
 * Detect the user's operating system
 */
export function detectUserOS(): string {
    const platform = navigator.platform.toLowerCase();

    if (platform.includes('win')) {
        return 'windows';
    } else if (platform.includes('mac')) {
        return 'macos';
    } else if (platform.includes('linux')) {
        return 'linux';
    } else if (/android/i.test(navigator.userAgent)) {
        return 'android';
    } else if (/iphone|ipad|ipod/i.test(navigator.userAgent)) {
        return 'ios';
    }

    return 'unknown';
}

/**
 * Settings management interfaces and functions
 */
export interface ServerSettings {
    general: {
        listen_address: string;
        listen_port: number;
        api_mode: boolean;
        max_pending_conns: number;
        max_concur_threads: number;
        update_interval: number;
        max_allowed_download_size: number;
        log_level: number;
    };
    subscription: {
        default_urls: string[];
        insert_urls: string[];
        prepend_insert: boolean;
        skip_failed_links: boolean;
        enable_insert: boolean;
        enable_sort: boolean;
        filter_script: string;
        sort_script: string;
    };
    rules: {
        enable_rule_gen: boolean;
        update_ruleset_on_request: boolean;
        overwrite_original_rules: boolean;
        async_fetch_ruleset: boolean;
        max_allowed_rulesets: number;
        max_allowed_rules: number;
    };
    cache: {
        cache_subscription: number;
        cache_config: number;
        cache_ruleset: number;
        serve_cache_on_fetch_fail: boolean;
    };
    custom: {
        emojis: Record<string, string>;
        renames: Record<string, string>;
        aliases: Record<string, string>;
    };
}

/**
 * Get current server settings
 */
export async function getServerSettings(): Promise<ServerSettings> {
    const response = await fetch('/api/admin/settings');

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<ServerSettings>;
}

/**
 * Update server settings
 */
export async function updateServerSettings(settings: Partial<ServerSettings>): Promise<ServerSettings> {
    const response = await fetch('/api/admin/settings', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(settings),
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<ServerSettings>;
}

/**
 * Export settings to file
 */
export async function exportSettings(format: 'yaml' | 'toml' | 'ini' = 'yaml'): Promise<Blob> {
    const response = await fetch(`/api/admin/settings/export?format=${format}`);

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.blob();
}

/**
 * Import settings from file
 */
export async function importSettings(file: File): Promise<ServerSettings> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/api/admin/settings/import', {
        method: 'POST',
        body: formData,
    });

    if (!response.ok) {
        const text = await response.text();
        try {
            const errorData = JSON.parse(text);
            throw errorData;
        } catch (err) {
            throw {
                error: `API Error (${response.status})`,
                details: typeof err === 'object' && err !== null ? err : text
            };
        }
    }

    return response.json() as Promise<ServerSettings>;
}

/**
 * Settings file operations
 */

/**
 * Read the pref.yml file content
 * If the file doesn't exist, it will create it from the example file
 */
export async function readSettingsFile(): Promise<string> {
    try {
        try {
            // Attempt to read pref.yml directly first
            return await readFile('pref.yml');
        } catch (err) {
            // If pref.yml doesn't exist or can't be read, create it from example
            console.log("pref.yml not found, creating from example...");
            const exampleContent = await readFile('pref.example.yml');
            await writeFile('pref.yml', exampleContent);
            return exampleContent;
        }
    } catch (error) {
        console.error("Error reading settings file:", error);
        throw error;
    }
}

/**
 * Write content to the pref.yml file
 */
export async function writeSettingsFile(content: string): Promise<void> {
    try {
        await writeFile('pref.yml', content);
    } catch (error) {
        console.error("Error writing settings file:", error);
        throw error;
    }
}

/**
 * Initialize settings with a specific preference path
 * Uses the WASM initialization function directly
 */
export async function initSettings(prefPath: string = ''): Promise<boolean> {
    try {
        const response = await fetch('/api/sub/init', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pref_path: prefPath }),
        });

        if (!response.ok) {
            const text = await response.text();
            try {
                const errorData = JSON.parse(text);
                throw errorData;
            } catch (err) {
                throw {
                    error: `API Error (${response.status})`,
                    details: typeof err === 'object' && err !== null ? err : text
                };
            }
        }

        const result = await response.json();
        return result.success;
    } catch (error) {
        console.error("Error initializing settings:", error);
        throw {
            error: "Failed to initialize settings",
            details: error instanceof Error ? error.message : String(error)
        };
    }
}

/**
 * Initializes the Subconverter Webapp VFS.
 * Calls the /api/init endpoint.
 * Returns true if the GitHub load was triggered (likely first run), false otherwise.
 */
export async function initializeWebApp(): Promise<{ success: boolean; githubLoadTriggered: boolean; message: string }> {
    const response = await fetch('/api/init');

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.details || data.error || `Failed to initialize webapp: ${response.statusText}`);
    }

    return data;
}
