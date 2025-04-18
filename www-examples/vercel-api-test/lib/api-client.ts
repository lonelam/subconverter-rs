// API client for interacting with the vercel-kv-vfs admin APIs

/**
 * File attributes interface matching the Rust FileAttributes struct
 */
export interface FileAttributes {
    size: number;
    created_at: number;
    modified_at: number;
    file_type: string;
    is_directory: boolean;
}

/**
 * Directory entry interface matching the Rust DirectoryEntry struct
 */
export interface DirectoryEntry {
    name: string;
    path: string;
    is_directory: boolean;
    attributes?: FileAttributes;
}

/**
 * Check if a file exists
 */
export async function checkFileExists(path: string): Promise<boolean> {
    try {
        const response = await fetch(`/api/admin/${path}?exists=true`);
        if (!response.ok) {
            return false;
        }
        const data = await response.json();
        return data.exists;
    } catch (error) {
        console.error("Error checking file existence:", error);
        return false;
    }
}

/**
 * Read a file's content
 */
export async function readFile(path: string): Promise<string | null> {
    try {
        const response = await fetch(`/api/admin/${path}`);
        if (!response.ok) {
            if (response.status === 404) {
                return null;
            }
            throw new Error(`Failed to read file: ${response.statusText}`);
        }
        const data = await response.json();

        // 直接返回文本内容，无需base64解码
        return data.content;
    } catch (error) {
        console.error(`Error reading file ${path}:`, error);
        throw error;
    }
}

/**
 * Write content to a file
 */
export async function writeFile(path: string, content: string): Promise<boolean> {
    try {
        // 直接发送文本内容，无需base64编码
        const response = await fetch(`/api/admin/${path}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ content }),
        });

        if (!response.ok) {
            throw new Error(`Failed to write file: ${response.statusText}`);
        }

        return true;
    } catch (error) {
        console.error(`Error writing file ${path}:`, error);
        throw error;
    }
}

/**
 * Delete a file
 */
export async function deleteFile(path: string): Promise<boolean> {
    try {
        const response = await fetch(`/api/admin/${path}`, {
            method: 'DELETE',
        });

        if (!response.ok) {
            throw new Error(`Failed to delete file: ${response.statusText}`);
        }

        return true;
    } catch (error) {
        console.error(`Error deleting file ${path}:`, error);
        throw error;
    }
}

/**
 * List directory contents
 */
export async function listDirectory(): Promise<any[]> {
    try {
        const response = await fetch('/api/admin/list');
        if (!response.ok) {
            throw new Error(`Failed to list directory: ${response.statusText}`);
        }
        const data = await response.json();
        return data.structure || [];
    } catch (error) {
        console.error("Error listing directory:", error);
        throw error;
    }
}

/**
 * Get file attributes
 */
export async function getFileAttributes(path: string): Promise<FileAttributes | null> {
    try {
        const response = await fetch(`/api/admin/${path}?attributes=true`);
        if (!response.ok) {
            if (response.status === 404) {
                return null;
            }
            throw new Error(`Failed to get file attributes: ${response.statusText}`);
        }
        const data = await response.json();
        return data.attributes;
    } catch (error) {
        console.error(`Error getting file attributes for ${path}:`, error);
        throw error;
    }
}

/**
 * Create a directory
 */
export async function createDirectory(path: string): Promise<boolean> {
    try {
        // Ensure path ends with a slash for directories
        const dirPath = path.endsWith('/') ? path : `${path}/`;

        const response = await fetch(`/api/admin/${dirPath}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                content: '',
                is_directory: true
            }),
        });

        if (!response.ok) {
            throw new Error(`Failed to create directory: ${response.statusText}`);
        }

        return true;
    } catch (error) {
        console.error(`Error creating directory ${path}:`, error);
        throw error;
    }
}

/**
 * Result of loading a directory from GitHub
 */
export interface LoadDirectoryResult {
    total_files: number;
    successful_files: number;
    failed_files: number;
    loaded_files: Array<{
        path: string;
        size: number;
        is_placeholder: boolean;
    }>;
}

/**
 * Load all files from a GitHub repository directory at once
 * @param path The directory path to load
 * @param shallow If true, only creates placeholders without downloading content
 */
export async function loadGitHubDirectory(path: string, shallow: boolean = true): Promise<LoadDirectoryResult> {
    try {
        const response = await fetch('/api/admin/github-load', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ path, shallow }),
        });

        if (!response.ok) {
            throw new Error(`Failed to load GitHub directory: ${response.statusText}`);
        }

        const result = await response.json();
        return result as LoadDirectoryResult;
    } catch (error) {
        console.error(`Error loading GitHub directory ${path}:`, error);
        throw error;
    }
} 