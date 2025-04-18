import React, { useState } from 'react';
import {
    Box, Button, Container, Paper, TextField, Typography,
    List, ListItem, ListItemText, Divider, CircularProgress,
    Accordion, AccordionSummary, AccordionDetails, Stack
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

// Debug panel for VFS operations
export default function DebugVfsPanel() {
    const [path, setPath] = useState('');
    const [loading, setLoading] = useState(false);
    const [response, setResponse] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);

    // Function to test listing directory
    const testListDirectory = async () => {
        setLoading(true);
        setError(null);
        setResponse(null);

        try {
            // Call the debug-kv-list endpoint
            const result = await fetch(`/api/admin/debug-kv-list?prefix=${encodeURIComponent(path)}`);

            if (!result.ok) {
                throw new Error(`HTTP error ${result.status}: ${result.statusText}`);
            }

            const data = await result.json();
            setResponse(data);
        } catch (err) {
            console.error('Error testing directory listing:', err);
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setLoading(false);
        }
    };

    // Function to load directory from GitHub
    const loadFromGithub = async () => {
        if (!path) {
            setError('Please enter a path');
            return;
        }

        setLoading(true);
        setError(null);
        setResponse(null);

        try {
            const result = await fetch('/api/admin/github-load', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ path }),
            });

            if (!result.ok) {
                throw new Error(`HTTP error ${result.status}: ${result.statusText}`);
            }

            const data = await result.json();
            setResponse({
                github_load_result: data
            });
        } catch (err) {
            console.error('Error loading from GitHub:', err);
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setLoading(false);
        }
    };

    // Function to display JSON data in a readable format
    const DisplayJson = ({ data }: { data: any }) => {
        if (!data) return null;

        if (typeof data === 'object' && data !== null) {
            return (
                <Box sx={{ my: 1 }}>
                    {Object.entries(data).map(([key, value], index) => (
                        <Accordion key={key} defaultExpanded={index === 0}>
                            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Typography variant="subtitle2">{key}</Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                                {typeof value === 'object' && value !== null ? (
                                    <DisplayJson data={value} />
                                ) : (
                                    <Typography variant="body2">
                                        {String(value)}
                                    </Typography>
                                )}
                            </AccordionDetails>
                        </Accordion>
                    ))}
                </Box>
            );
        }

        return <Typography variant="body2">{String(data)}</Typography>;
    };

    // Function to display a list of strings
    const DisplayList = ({ title, items }: { title: string, items: string[] }) => {
        if (!items || items.length === 0) return null;

        return (
            <Box sx={{ my: 2 }}>
                <Typography variant="subtitle2">{title} ({items.length})</Typography>
                <List dense>
                    {items.map((item, index) => (
                        <ListItem key={index}>
                            <ListItemText primary={item} />
                        </ListItem>
                    ))}
                </List>
            </Box>
        );
    };

    return (
        <Paper sx={{ p: 3 }}>
            <Typography variant="h5" gutterBottom>
                VFS Debug Panel
            </Typography>

            <Box sx={{ mb: 3 }}>
                <TextField
                    fullWidth
                    label="Directory Path"
                    placeholder="Enter a path (e.g. 'base/rules' or empty for root)"
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    variant="outlined"
                    helperText="Enter the path to test (leave empty for root)"
                    sx={{ mb: 2 }}
                />

                <Stack direction="row" spacing={2}>
                    <Button
                        variant="contained"
                        color="primary"
                        onClick={testListDirectory}
                        disabled={loading}
                        sx={{ flexGrow: 1 }}
                    >
                        {loading ? <CircularProgress size={24} /> : "Test Directory"}
                    </Button>
                    <Button
                        variant="outlined"
                        color="secondary"
                        onClick={loadFromGithub}
                        disabled={loading}
                        sx={{ flexGrow: 1 }}
                    >
                        Load From GitHub
                    </Button>
                </Stack>
            </Box>

            {error && (
                <Paper sx={{ p: 2, mb: 3, bgcolor: 'error.light' }}>
                    <Typography color="error.contrastText">Error: {error}</Typography>
                </Paper>
            )}

            {response && (
                <Box sx={{ mt: 3 }}>
                    <Divider sx={{ mb: 2 }} />

                    {response.js_binding && response.rust_implementation && (
                        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                            <Box sx={{ flex: 1 }}>
                                <Typography variant="h6">Javascript Binding</Typography>
                                <DisplayJson data={response.js_binding} />
                            </Box>

                            <Box sx={{ flex: 1 }}>
                                <Typography variant="h6">Rust Implementation</Typography>
                                <DisplayJson data={response.rust_implementation} />
                            </Box>
                        </Stack>
                    )}

                    {response.github_load_result && (
                        <>
                            <Typography variant="h6">GitHub Load Result</Typography>
                            <DisplayJson data={response.github_load_result} />

                            {response.github_load_result.loaded_files && (
                                <DisplayList
                                    title="Loaded Files"
                                    items={response.github_load_result.loaded_files.map((f: any) => f.path)}
                                />
                            )}
                        </>
                    )}

                    {response.raw_kv_keys && (
                        <DisplayList title="Raw KV Keys" items={response.raw_kv_keys} />
                    )}

                    {response.entries && (
                        <DisplayList
                            title="Directory Entries"
                            items={response.entries.map((e: any) => `${e.name} (${e.is_directory ? 'dir' : 'file'})`)}
                        />
                    )}
                </Box>
            )}
        </Paper>
    );
} 