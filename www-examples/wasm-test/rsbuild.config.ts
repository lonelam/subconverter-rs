import { defineConfig } from '@rsbuild/core';
import { pluginReact } from '@rsbuild/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [pluginReact()],
  dev: {
    assetPrefix: './',
  },
  source: {
    alias: {
      '@': path.resolve(process.cwd(), './src'),
    },
  },
});
