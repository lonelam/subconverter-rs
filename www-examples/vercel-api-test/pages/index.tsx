import React, { useState } from 'react';
import { Container, Box, Typography, Paper } from '@mui/material';
import Grid from '@mui/material/Grid';
import CodeEditor from '../components/CodeEditor';
import ArboristFileExplorer from '../components/ArboristFileExplorer';

export default function Home() {
    const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);

    const handleFileSelect = (path: string) => {
        setSelectedFilePath(path);
    };

    return (
        <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Typography variant="h4" gutterBottom>
                Subconverter Admin
            </Typography>

            <Grid container spacing={2} sx={{ height: 'calc(100vh - 150px)' }}>
                {/* 文件浏览器 */}
                <Grid size={{ xs: 12, md: 3, lg: 2.5 }}>
                    <Paper sx={{ height: '100%', overflow: 'hidden' }}>
                        <ArboristFileExplorer onFileSelect={handleFileSelect} />
                    </Paper>
                </Grid>

                {/* 代码编辑器 */}
                <Grid size={{ xs: 12, md: 9, lg: 9.5 }}>
                    <Paper sx={{ height: '100%', overflow: 'hidden' }}>
                        <CodeEditor filePath={selectedFilePath} />
                    </Paper>
                </Grid>
            </Grid>
        </Container>
    );
} 