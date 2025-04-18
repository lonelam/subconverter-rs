import React, { useState, useEffect } from 'react';
import { Box, Button, CircularProgress, Typography, Chip, Tooltip } from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import InfoIcon from '@mui/icons-material/Info';
import Editor from '@monaco-editor/react';
import { readFile, writeFile, getFileAttributes, FileAttributes } from '../lib/api-client';

interface CodeEditorProps {
    filePath: string | null;
}

// Helper function to format file size
const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

// Helper function to format timestamp
const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
};

export default function CodeEditor({ filePath }: CodeEditorProps) {
    const [content, setContent] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [language, setLanguage] = useState('plaintext');
    const [fileAttributes, setFileAttributes] = useState<FileAttributes | null>(null);

    useEffect(() => {
        if (!filePath) {
            setContent(null);
            setError(null);
            setFileAttributes(null);
            return;
        }

        const loadFile = async () => {
            setLoading(true);
            setError(null);
            try {
                const fileContent = await readFile(filePath);
                setContent(fileContent || '');

                // Set language based on file extension
                const extension = filePath.split('.').pop()?.toLowerCase() || '';
                setLanguage(getLanguageFromExtension(extension));

                // Load file attributes
                try {
                    const attributes = await getFileAttributes(filePath);
                    setFileAttributes(attributes);
                } catch (attrError) {
                    console.error('Error loading file attributes:', attrError);
                    // Don't block the file loading if attributes fail
                }
            } catch (err) {
                console.error('Error loading file:', err);
                setError(`Failed to load file: ${err.message || 'Unknown error'}`);
                setContent(null);
            } finally {
                setLoading(false);
            }
        };

        loadFile();
    }, [filePath]);

    const handleSave = async () => {
        if (!filePath || content === null) return;

        setSaving(true);
        setError(null);

        try {
            await writeFile(filePath, content);

            // Refresh file attributes after save
            try {
                const attributes = await getFileAttributes(filePath);
                setFileAttributes(attributes);
            } catch (attrError) {
                console.error('Error refreshing file attributes:', attrError);
            }

            setSaving(false);
        } catch (err) {
            console.error('Error saving file:', err);
            setError(`Failed to save file: ${err.message || 'Unknown error'}`);
            setSaving(false);
        }
    };

    const getLanguageFromExtension = (extension: string): string => {
        const languageMap: Record<string, string> = {
            'js': 'javascript',
            'ts': 'typescript',
            'json': 'json',
            'md': 'markdown',
            'txt': 'plaintext',
            'html': 'html',
            'css': 'css',
            'ini': 'ini',
            'yml': 'yaml',
            'yaml': 'yaml',
            'rs': 'rust',
            'py': 'python',
            'sh': 'shell',
            'bash': 'shell',
            'list': 'plaintext',
        };

        return languageMap[extension] || 'plaintext';
    };

    const handleEditorChange = (value: string | undefined) => {
        setContent(value || '');
    };

    return (
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <Box sx={{
                display: 'flex',
                justifyContent: 'space-between',
                p: 1,
                borderBottom: '1px solid #eee',
                alignItems: 'center',
                flexWrap: 'wrap'
            }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="subtitle1">
                        {filePath ? filePath : 'No file selected'}
                    </Typography>
                    {fileAttributes && (
                        <Tooltip
                            title={
                                <React.Fragment>
                                    <Typography variant="caption" display="block">
                                        <strong>Size:</strong> {formatFileSize(fileAttributes.size)}
                                    </Typography>
                                    <Typography variant="caption" display="block">
                                        <strong>Type:</strong> {fileAttributes.file_type}
                                    </Typography>
                                    <Typography variant="caption" display="block">
                                        <strong>Created:</strong> {formatTimestamp(fileAttributes.created_at)}
                                    </Typography>
                                    <Typography variant="caption" display="block">
                                        <strong>Modified:</strong> {formatTimestamp(fileAttributes.modified_at)}
                                    </Typography>
                                </React.Fragment>
                            }
                            arrow
                        >
                            <Chip
                                icon={<InfoIcon />}
                                label={formatFileSize(fileAttributes.size)}
                                size="small"
                                variant="outlined"
                            />
                        </Tooltip>
                    )}
                </Box>
                <Button
                    startIcon={saving ? <CircularProgress size={18} /> : <SaveIcon />}
                    variant="contained"
                    size="small"
                    disabled={!filePath || saving || loading || content === null}
                    onClick={handleSave}
                >
                    {saving ? 'Saving...' : 'Save'}
                </Button>
            </Box>

            <Box sx={{ flexGrow: 1, position: 'relative' }}>
                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                        <CircularProgress />
                    </Box>
                ) : error ? (
                    <Box sx={{ p: 2, color: 'error.main' }}>{error}</Box>
                ) : !filePath ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: 'text.secondary' }}>
                        Select a file from the explorer to edit
                    </Box>
                ) : (
                    <Editor
                        height="100%"
                        language={language}
                        value={content || ''}
                        onChange={handleEditorChange}
                        theme="vs-light"
                        options={{
                            minimap: { enabled: false },
                            scrollBeyondLastLine: false,
                            fontSize: 14,
                            lineNumbers: 'on',
                            renderLineHighlight: 'all',
                            automaticLayout: true,
                        }}
                    />
                )}
            </Box>
        </Box>
    );
} 