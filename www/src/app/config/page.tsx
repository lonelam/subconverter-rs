"use client";

import { useState } from "react";
import Link from "next/link";
import CodeEditor from "@/components/CodeEditor";
import { copyToClipboard } from "@/lib/clipboard";

export default function ConfigEditor() {
    const [activeTab, setActiveTab] = useState("general");
    const [configName, setConfigName] = useState("My Custom Config");
    const [generatedLink, setGeneratedLink] = useState("");
    const [configContent, setConfigContent] = useState(`# My Subconverter Configuration

[custom]
enable_rule_generator=true
overwrite_original_rules=true

# Add your custom configuration here
`);

    const handleSaveConfig = () => {
        // Generate a unique ID for the config
        const configId = Math.random().toString(36).substring(2, 15);
        const baseUrl = window.location.origin;
        const link = `${baseUrl}/api/subconverter?config=${configId}`;

        setGeneratedLink(link);

        // In a real implementation, this would save the config to a database
        console.log("Config saved:", configName);
    };

    const handleConfigChange = (value: string | undefined) => {
        setConfigContent(value || '');
    };

    return (
        <main className="flex min-h-screen flex-col items-center p-8">
            <div className="z-10 max-w-5xl w-full items-center font-mono text-sm">
                <div className="flex justify-between items-center mb-8">
                    <h1 className="text-3xl font-bold">Config Editor</h1>
                    <Link
                        href="/"
                        className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
                    >
                        Back to Home
                    </Link>
                </div>

                <div className="bg-white/5 p-6 rounded-lg shadow-md mb-8">
                    <div className="flex mb-4">
                        <input
                            type="text"
                            value={configName}
                            onChange={(e) => setConfigName(e.target.value)}
                            placeholder="Config Name"
                            className="w-full p-2 border border-gray-300 rounded-l bg-white/10"
                        />
                        <button
                            onClick={handleSaveConfig}
                            className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-r"
                        >
                            Save Config
                        </button>
                    </div>

                    {generatedLink && (
                        <div className="mt-4 p-4 bg-gray-800 rounded">
                            <p className="text-sm mb-2">Your generated link:</p>
                            <div className="flex">
                                <input
                                    type="text"
                                    readOnly
                                    value={generatedLink}
                                    className="w-full p-2 bg-gray-700 rounded-l"
                                />
                                <button
                                    onClick={() => copyToClipboard(generatedLink)}
                                    className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-r"
                                >
                                    Copy
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                <div className="bg-white/5 rounded-lg shadow-md">
                    <div className="flex border-b border-gray-700">
                        <button
                            className={`px-4 py-2 ${activeTab === "general"
                                ? "bg-blue-600 text-white"
                                : "bg-transparent"
                                }`}
                            onClick={() => setActiveTab("general")}
                        >
                            General
                        </button>
                        <button
                            className={`px-4 py-2 ${activeTab === "proxy"
                                ? "bg-blue-600 text-white"
                                : "bg-transparent"
                                }`}
                            onClick={() => setActiveTab("proxy")}
                        >
                            Proxy Settings
                        </button>
                        <button
                            className={`px-4 py-2 ${activeTab === "rules"
                                ? "bg-blue-600 text-white"
                                : "bg-transparent"
                                }`}
                            onClick={() => setActiveTab("rules")}
                        >
                            Rules
                        </button>
                        <button
                            className={`px-4 py-2 ${activeTab === "advanced"
                                ? "bg-blue-600 text-white"
                                : "bg-transparent"
                                }`}
                            onClick={() => setActiveTab("advanced")}
                        >
                            Advanced
                        </button>
                        <button
                            className={`px-4 py-2 ${activeTab === "filebrowser"
                                ? "bg-blue-600 text-white"
                                : "bg-transparent"
                                }`}
                            onClick={() => setActiveTab("filebrowser")}
                        >
                            File Browser
                        </button>
                    </div>

                    <div className="p-6">
                        {activeTab === "general" && (
                            <div className="space-y-4">
                                <div>
                                    <label htmlFor="target" className="block text-sm font-medium mb-1">
                                        Target Format
                                    </label>
                                    <select
                                        id="target"
                                        className="w-full p-2 border border-gray-300 rounded bg-white/10"
                                    >
                                        <option value="clash">Clash</option>
                                        <option value="surge">Surge</option>
                                        <option value="quantumult">Quantumult</option>
                                        <option value="quanx">Quantumult X</option>
                                        <option value="loon">Loon</option>
                                        <option value="ss">SS</option>
                                        <option value="ssr">SSR</option>
                                        <option value="v2ray">V2Ray</option>
                                    </select>
                                </div>

                                <div>
                                    <label htmlFor="subscriptionUrl" className="block text-sm font-medium mb-1">
                                        Subscription URL
                                    </label>
                                    <input
                                        type="url"
                                        id="subscriptionUrl"
                                        placeholder="https://example.com/subscription"
                                        className="w-full p-2 border border-gray-300 rounded bg-white/10"
                                    />
                                </div>

                                <div>
                                    <label htmlFor="includedTypes" className="block text-sm font-medium mb-1">
                                        Include Proxy Types
                                    </label>
                                    <div className="grid grid-cols-2 gap-2">
                                        <div className="flex items-center">
                                            <input type="checkbox" id="typeSSR" className="mr-2" />
                                            <label htmlFor="typeSSR">SSR</label>
                                        </div>
                                        <div className="flex items-center">
                                            <input type="checkbox" id="typeSS" className="mr-2" />
                                            <label htmlFor="typeSS">SS</label>
                                        </div>
                                        <div className="flex items-center">
                                            <input type="checkbox" id="typeVMess" className="mr-2" />
                                            <label htmlFor="typeVMess">VMess</label>
                                        </div>
                                        <div className="flex items-center">
                                            <input type="checkbox" id="typeTrojan" className="mr-2" />
                                            <label htmlFor="typeTrojan">Trojan</label>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {activeTab === "proxy" && (
                            <div className="space-y-4">
                                <p>Proxy configuration settings go here.</p>
                            </div>
                        )}

                        {activeTab === "rules" && (
                            <div className="space-y-4">
                                <p>Rule configuration settings go here.</p>
                            </div>
                        )}

                        {activeTab === "advanced" && (
                            <div className="space-y-4">
                                <p className="mb-4">Edit your configuration directly:</p>
                                <div className="border border-gray-700 rounded-md h-[500px]">
                                    <CodeEditor
                                        filePath="config.ini"
                                        language="ini"
                                        onChange={handleConfigChange}
                                    />
                                </div>
                            </div>
                        )}

                        {activeTab === "filebrowser" && (
                            <div className="space-y-4">
                                <p className="mb-4">Access the file browser to manage your configuration files:</p>
                                <Link
                                    href="/admin"
                                    className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded inline-flex items-center"
                                >
                                    Open File Browser
                                </Link>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </main>
    );
} 