"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { ShortUrlData, listShortUrls, deleteShortUrl, createShortUrl, updateShortUrl, moveShortUrl } from "@/lib/api-client";
import { useRouter } from "next/navigation";
import { copyToClipboard } from "@/lib/clipboard";

export default function SavedLinks() {
    const [links, setLinks] = useState<ShortUrlData[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showNewLinkForm, setShowNewLinkForm] = useState(false);
    const [newLink, setNewLink] = useState({ target_url: "", custom_id: "", description: "" });
    const [editingLink, setEditingLink] = useState<ShortUrlData | null>(null);
    const [editCustomId, setEditCustomId] = useState<string>('');
    const router = useRouter();

    // Load links on component mount
    useEffect(() => {
        loadLinks();
    }, []);

    const loadLinks = async () => {
        try {
            setLoading(true);
            const data = await listShortUrls();
            setLinks(data);
            setError(null);
        } catch (err: any) {
            setError(err.error || "Failed to load links");
            console.error("Error loading links:", err);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm("Are you sure you want to delete this short URL?")) {
            return;
        }

        try {
            await deleteShortUrl(id);
            setLinks(links.filter(link => link.id !== id));
        } catch (err: any) {
            setError(err.error || "Failed to delete link");
            console.error("Error deleting link:", err);
        }
    };

    const handleCreateSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newLink.target_url) {
            setError("Target URL is required");
            return;
        }

        try {
            const createdLink = await createShortUrl({
                target_url: newLink.target_url,
                custom_id: newLink.custom_id || undefined,
                description: newLink.description || undefined
            });

            setLinks([createdLink, ...links]);
            setNewLink({ target_url: "", custom_id: "", description: "" });
            setShowNewLinkForm(false);
            setError(null);
        } catch (err: any) {
            setError(err.error || "Failed to create short URL");
            console.error("Error creating short URL:", err);
        }
    };

    const handleEditSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingLink) return;

        try {
            let updatedLink;

            // If custom ID is provided, move the short URL to a new ID
            if (editCustomId) {
                updatedLink = await moveShortUrl(editingLink.id, editCustomId);
            } else {
                // Otherwise, just update the existing short URL
                updatedLink = await updateShortUrl(editingLink.id, {
                    target_url: editingLink.target_url,
                    description: editingLink.description
                });
            }

            setLinks(prevLinks => {
                // If we moved to a new ID, we need to filter out the old link and add the new one
                if (editCustomId) {
                    return [
                        updatedLink,
                        ...prevLinks.filter(link => link.id !== editingLink.id)
                    ];
                }
                // Otherwise, replace the existing link
                else {
                    return prevLinks.map(link =>
                        link.id === updatedLink.id ? updatedLink : link
                    );
                }
            });
            setEditingLink(null);
            setEditCustomId('');
            setError(null);
        } catch (err: any) {
            setError(err.error || "Failed to update short URL");
            console.error("Error updating short URL:", err);
        }
    };

    // Format timestamp to human-readable date
    const formatDate = (timestamp: number) => {
        return new Date(timestamp * 1000).toLocaleString();
    };

    // When setting the editing link, get the existing custom ID
    const startEditing = (link: ShortUrlData) => {
        setEditingLink(link);
        // We need to load the actual custom ID value
        // This would typically come from the API but we'll use the link ID as a fallback
        setEditCustomId('');
    };

    return (
        <main className="flex min-h-screen flex-col items-center p-8">
            <div className="z-10 max-w-5xl w-full items-center font-mono text-sm">
                <div className="flex justify-between items-center mb-8">
                    <h1 className="text-3xl font-bold">My Short URLs</h1>
                    <div className="flex gap-2">
                        <button
                            onClick={() => setShowNewLinkForm(!showNewLinkForm)}
                            className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                        >
                            {showNewLinkForm ? "Cancel" : "Create New Short URL"}
                        </button>
                        <Link
                            href="/"
                            className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
                        >
                            Back to Home
                        </Link>
                    </div>
                </div>

                {error && (
                    <div className="bg-red-500/20 border border-red-500 text-red-100 p-4 mb-6 rounded-lg">
                        {error}
                    </div>
                )}

                {showNewLinkForm && (
                    <div className="bg-white/10 p-6 rounded-lg shadow-md mb-6">
                        <h2 className="text-xl font-bold mb-4">Create New Short URL</h2>
                        <form onSubmit={handleCreateSubmit}>
                            <div className="mb-4">
                                <label className="block mb-2">Target URL*</label>
                                <input
                                    type="url"
                                    required
                                    className="w-full p-2 bg-black/30 border border-gray-700 rounded"
                                    value={newLink.target_url}
                                    onChange={(e) => setNewLink({ ...newLink, target_url: e.target.value })}
                                    placeholder="https://example.com"
                                />
                            </div>
                            <div className="mb-4">
                                <label className="block mb-2">Custom ID (optional)</label>
                                <input
                                    type="text"
                                    className="w-full p-2 bg-black/30 border border-gray-700 rounded"
                                    value={newLink.custom_id}
                                    onChange={(e) => setNewLink({ ...newLink, custom_id: e.target.value })}
                                    placeholder="my-custom-id"
                                />
                            </div>
                            <div className="mb-4">
                                <label className="block mb-2">Description (optional)</label>
                                <input
                                    type="text"
                                    className="w-full p-2 bg-black/30 border border-gray-700 rounded"
                                    value={newLink.description}
                                    onChange={(e) => setNewLink({ ...newLink, description: e.target.value })}
                                    placeholder="Description for this URL"
                                />
                            </div>
                            <button
                                type="submit"
                                className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
                            >
                                Create Short URL
                            </button>
                        </form>
                    </div>
                )}

                {editingLink && (
                    <div className="bg-white/10 p-6 rounded-lg shadow-md mb-6">
                        <h2 className="text-xl font-bold mb-4">Edit Short URL</h2>
                        <form onSubmit={handleEditSubmit}>
                            <div className="mb-4">
                                <label className="block mb-2">Target URL*</label>
                                <input
                                    type="url"
                                    required
                                    className="w-full p-2 bg-black/30 border border-gray-700 rounded"
                                    value={editingLink.target_url}
                                    onChange={(e) => setEditingLink({ ...editingLink, target_url: e.target.value })}
                                />
                            </div>
                            <div className="mb-4">
                                <label className="block mb-2">Custom ID (alias)</label>
                                <input
                                    type="text"
                                    className="w-full p-2 bg-black/30 border border-gray-700 rounded"
                                    value={editCustomId}
                                    onChange={(e) => setEditCustomId(e.target.value)}
                                    placeholder="my-custom-id"
                                />
                                <p className="text-xs text-gray-400 mt-1">
                                    Enter a new custom ID to move this URL to a different alias.
                                    This will create a new short URL with the same target URL but a different path.
                                    Leave blank to keep the current ID.
                                </p>
                            </div>
                            <div className="mb-4">
                                <label className="block mb-2">Description</label>
                                <input
                                    type="text"
                                    className="w-full p-2 bg-black/30 border border-gray-700 rounded"
                                    value={editingLink.description || ""}
                                    onChange={(e) => setEditingLink({ ...editingLink, description: e.target.value || undefined })}
                                />
                            </div>
                            <div className="flex gap-2">
                                <button
                                    type="submit"
                                    className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
                                >
                                    Save Changes
                                </button>
                                <button
                                    type="button"
                                    className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
                                    onClick={() => setEditingLink(null)}
                                >
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                )}

                <div className="bg-white/5 p-6 rounded-lg shadow-md">
                    {loading ? (
                        <div className="text-center py-8">
                            <p className="text-lg">Loading short URLs...</p>
                        </div>
                    ) : links.length > 0 ? (
                        <div className="space-y-4">
                            {links.map((link) => (
                                <div
                                    key={link.id}
                                    className="border border-gray-700 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between"
                                >
                                    <div className="mb-4 md:mb-0 flex-1">
                                        <div className="flex items-center gap-2">
                                            <h3 className="text-xl font-semibold">
                                                {link.description || link.id}
                                            </h3>
                                            {link.custom_id && (
                                                <span className="bg-purple-500/30 text-purple-300 text-xs px-2 py-1 rounded-full">
                                                    Custom ID
                                                </span>
                                            )}
                                        </div>

                                        <div className="mt-3 flex flex-col gap-1">
                                            <div className="flex items-center">
                                                <span className="text-sm font-medium text-gray-400 w-20">Short URL:</span>
                                                <a
                                                    href={link.short_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-sm text-blue-400 hover:text-blue-300 underline"
                                                >
                                                    {link.short_url.replace(/^https?:\/\/[^/]+/, '')}
                                                </a>
                                            </div>

                                            <div className="flex items-center">
                                                <span className="text-sm font-medium text-gray-400 w-20">Target:</span>
                                                <a
                                                    href={link.target_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-sm text-gray-300 hover:text-gray-100 truncate max-w-lg"
                                                >
                                                    {link.target_url}
                                                </a>
                                            </div>
                                        </div>

                                        <div className="mt-2 flex flex-wrap gap-3 text-xs">
                                            <span className="bg-gray-700/50 px-2 py-1 rounded-md">
                                                Created: {formatDate(link.created_at)}
                                            </span>
                                            <span className="bg-gray-700/50 px-2 py-1 rounded-md">
                                                Clicks: {link.use_count}
                                            </span>
                                            {link.last_used && (
                                                <span className="bg-gray-700/50 px-2 py-1 rounded-md">
                                                    Last used: {formatDate(link.last_used)}
                                                </span>
                                            )}
                                            <span className="bg-gray-700/50 px-2 py-1 rounded-md">
                                                ID: {link.id}
                                            </span>
                                        </div>
                                    </div>
                                    <div className="flex flex-col md:flex-row gap-2">
                                        <button
                                            onClick={() => copyToClipboard(link.short_url)}
                                            className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded flex items-center justify-center"
                                        >
                                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                            Copy
                                        </button>
                                        <button
                                            onClick={() => startEditing(link)}
                                            className="bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded flex items-center justify-center"
                                        >
                                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                            </svg>
                                            Edit
                                        </button>
                                        <button
                                            onClick={() => handleDelete(link.id)}
                                            className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded flex items-center justify-center"
                                        >
                                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                            </svg>
                                            Delete
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="text-center py-8">
                            <p className="text-lg mb-4">You don't have any short URLs yet.</p>
                            <button
                                onClick={() => setShowNewLinkForm(true)}
                                className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
                            >
                                Create Your First Short URL
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </main>
    );
} 