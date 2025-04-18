import fs from 'fs';
import path from 'path';
import withRspack from 'next-rspack';
const __dirname = import.meta.dirname;

/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    // Allows importing wasm files from pkg directory
    transpilePackages: ['subconverter-wasm'],
    // Output configuration for Vercel deployment
    // output: 'standalone',
    // Webpack config to support WASM
    webpack: (config, { isServer }) => {
        // Support for WebAssembly
        config.experiments = {
            ...config.experiments,
            asyncWebAssembly: true,
        };

        // Add a copy plugin to copy the WASM file to the output directory
        if (isServer) {
            // For server-side (Node.js environment)
            config.plugins.push({
                apply: (compiler) => {
                    compiler.hooks.afterEmit.tap('CopyWasmPlugin', (compilation) => {
                        // Source WASM file
                        const sourcePath = path.resolve(__dirname, 'node_modules/subconverter-wasm/subconverter_bg.wasm');

                        // Multiple destination paths for different environments
                        const destinations = [
                            // For development
                            path.resolve(__dirname, '.next/server/subconverter_bg.wasm'),
                            // For Vercel production (.output)
                            path.resolve(__dirname, '.output/server/subconverter_bg.wasm'),
                            // For Vercel serverless functions
                            path.resolve(__dirname, '.vercel/output/functions/api/subconverter_bg.wasm')
                        ];

                        // Copy to each destination
                        for (const destPath of destinations) {
                            const destDir = path.dirname(destPath);
                            // Create the directory if it doesn't exist
                            if (!fs.existsSync(destDir)) {
                                fs.mkdirSync(destDir, { recursive: true });
                            }

                            // Copy the file
                            try {
                                fs.copyFileSync(sourcePath, destPath);
                                console.log(`✅ Copied WASM file from ${sourcePath} to ${destPath}`);
                            } catch (err) {
                                console.error(`❌ Error copying WASM file to ${destPath}: ${err.message}`);
                            }
                        }
                    });
                }
            });
        }

        return config;
    },
    async rewrites() {
        // In development, rewrite requests to the root /api to our pages/api
        // This is already handled in production by Vercel
        return [
            // Rewrite all API calls to the pages/api directory
            {
                source: '/api/:path*',
                destination: '/api/:path*',
            },
        ];
    },
};

export default (nextConfig); 