import React from 'react';
import dynamic from 'next/dynamic';
import { Box, Typography, Container, Paper } from '@mui/material';

// Dynamically import the Debug component with no SSR
// This is necessary because it uses browser-only APIs
const DebugVfsPanel = dynamic(() => import('../components/DebugVfsPanel'), {
    ssr: false,
});

export default function DebugPage() {
    return (
        <Container maxWidth="lg" sx={{ py: 4 }}>
            <Paper sx={{ p: 3, mb: 4 }}>
                <Typography variant="h4" component="h1" gutterBottom>
                    Subconverter-rs Debug Tools
                </Typography>
                <Typography variant="body1" paragraph>
                    This page contains debugging tools for the VFS (Virtual File System) and other components.
                    Use these tools to diagnose issues with file loading, KV store operations, and GitHub synchronization.
                </Typography>
            </Paper>

            {/* Include the debug VFS panel */}
            <DebugVfsPanel />
        </Container>
    );
} 