# Rsbuild project

## Setup

Install dependencies:

```bash
npm install
# or
pnpm install
```

## Development

Start the development server:

```bash
npm run dev
# or
pnpm dev
```

The application will open in your browser at http://localhost:8080.

## Usage

The application has two main sections:

1. **Initialize Settings**: This section allows you to initialize the subconverter settings with YAML, TOML, or INI content. You can either paste your own settings or use the "Load Example Settings" button.

2. **Convert Subscription**: This section allows you to convert a subscription by providing a JSON query. You can either paste your own query or use the "Load Example Query" button.

After converting a subscription, the result will be displayed in the "Conversion Result" section.

## Building for Production

To build the application for production:

```bash
npm run build
# or
pnpm build
```

The build output will be in the `dist` directory and will include the WASM files.

## Project Structure

- `src/App.tsx`: The main React component that implements the WASM functionality
- `src/wasm-pkg.d.ts`: TypeScript declarations for the WASM module
- `rsbuild.config.ts`: Build configuration that includes copying the WASM files

## Note

This is a testing project and not intended for production use. It demonstrates how to use the subconverter-rs WASM module in a React application.
