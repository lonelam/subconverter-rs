import React, { useState, useEffect } from 'react';
import { Box, Typography, IconButton, TextField, Button, Tooltip, Dialog, DialogTitle, DialogContent, DialogActions, CircularProgress } from '@mui/material';
import TreeView from '@mui/lab/TreeView';
import TreeItem from '@mui/lab/TreeItem';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import CreateNewFolderIcon from '@mui/icons-material/CreateNewFolder';
import FolderIcon from '@mui/icons-material/Folder';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import RefreshIcon from '@mui/icons-material/Refresh';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';

import { checkFileExists, deleteFile, writeFile, getFileAttributes, createDirectory, FileAttributes, loadGitHubDirectory } from '../lib/api-client';

// 客户端专用组件
const ClientOnly = ({ children }) => {
    const [isClient, setIsClient] = useState(false);

    useEffect(() => {
        setIsClient(true);
    }, []);

    return isClient ? children : <Box sx={{ p: 2, textAlign: 'center' }}><CircularProgress size={24} /></Box>;
};

// Types
interface TreeNode {
    id: string;
    name: string;
    type: 'file' | 'folder';
    path: string;
    children?: TreeNode[];
    attributes?: FileAttributes;
    isPlaceholder?: boolean;
}

interface SimpleFileExplorerProps {
    onFileSelect: (path: string) => void;
    rootPath?: string;
}

// Helper function to format file size
const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

export default function SimpleFileExplorer({ onFileSelect, rootPath = '' }: SimpleFileExplorerProps) {
    const [treeData, setTreeData] = useState<TreeNode[]>([]);
    const [expanded, setExpanded] = useState<string[]>([]);
    const [selected, setSelected] = useState<string>('');
    const [loading, setLoading] = useState(false);
    const [refreshTrigger, setRefreshTrigger] = useState(0);

    // New item creation state
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [newItemName, setNewItemName] = useState('');
    const [newItemType, setNewItemType] = useState<'file' | 'folder'>('file');

    // File attribute dialog state
    const [attributesDialogOpen, setAttributesDialogOpen] = useState(false);
    const [selectedNodeForAttributes, setSelectedNodeForAttributes] = useState<TreeNode | null>(null);

    // Convert flat list to tree structure
    const convertToTreeNodes = (items: any[]): TreeNode[] => {
        // First create a map of all nodes
        const nodeMap = new Map<string, TreeNode>();

        items.forEach(item => {
            nodeMap.set(item.id, {
                id: item.id,
                name: item.name,
                type: item.type,
                path: item.id,
                children: item.type === 'folder' ? [] : undefined,
                attributes: item.attributes,
                isPlaceholder: item.isPlaceholder
            });
        });

        // Now build the tree
        const rootNodes: TreeNode[] = [];

        items.forEach(item => {
            const node = nodeMap.get(item.id);
            if (!node) return;

            if (item.id.includes('/')) {
                // This is a child node
                const parentPath = item.id.substring(0, item.id.lastIndexOf('/'));
                const parent = nodeMap.get(parentPath);

                if (parent && parent.children) {
                    parent.children.push(node);
                } else {
                    // If parent not found, add to root
                    rootNodes.push(node);
                }
            } else {
                // This is a root node
                rootNodes.push(node);
            }
        });

        // Sort nodes (folders first, then alphabetically)
        const sortNodes = (nodes: TreeNode[]): TreeNode[] => {
            return nodes.sort((a, b) => {
                if (a.type === 'folder' && b.type !== 'folder') return -1;
                if (a.type !== 'folder' && b.type === 'folder') return 1;
                return a.name.localeCompare(b.name);
            }).map(node => {
                if (node.children) {
                    node.children = sortNodes(node.children);
                }
                return node;
            });
        };

        return sortNodes(rootNodes);
    };

    // Fetch directory structure
    const fetchDirectoryStructure = async () => {
        setLoading(true);
        try {
            const response = await fetch('/api/admin/list');
            if (!response.ok) {
                throw new Error(`Failed to fetch directory structure: ${response.statusText}`);
            }
            const data = await response.json();

            // Convert the data to our tree format
            const treeNodes = convertToTreeNodes(data.structure || []);
            setTreeData(treeNodes);

            // Auto-expand first level folders
            const firstLevelIds = treeNodes.filter(node => node.type === 'folder').map(node => node.id);
            setExpanded(firstLevelIds);
        } catch (error) {
            console.error('Error fetching directory structure:', error);
            // Fallback data
            setTreeData([
                {
                    id: 'configs',
                    name: 'configs',
                    type: 'folder',
                    path: 'configs',
                    children: [
                        {
                            id: 'configs/config.ini',
                            name: 'config.ini',
                            type: 'file',
                            path: 'configs/config.ini'
                        }
                    ]
                },
                {
                    id: 'README.md',
                    name: 'README.md',
                    type: 'file',
                    path: 'README.md'
                }
            ]);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDirectoryStructure();
    }, [refreshTrigger]);

    const handleToggle = (event: React.SyntheticEvent, nodeIds: string[]) => {
        setExpanded(nodeIds);
    };

    const handleSelect = (event: React.SyntheticEvent, nodeId: string) => {
        setSelected(nodeId);

        // Find the selected node
        const findNode = (nodes: TreeNode[], id: string): TreeNode | null => {
            for (const node of nodes) {
                if (node.id === id) return node;
                if (node.children) {
                    const found = findNode(node.children, id);
                    if (found) return found;
                }
            }
            return null;
        };

        const selectedNode = findNode(treeData, nodeId);
        if (selectedNode && selectedNode.type === 'file') {
            onFileSelect(selectedNode.path);
        }
    };

    const handleCreateNewItem = () => {
        setIsCreatingNew(true);
        setNewItemName('');
    };

    const handleSaveNewItem = async () => {
        if (!newItemName) return;

        // Determine parent path based on selection
        let parentPath = '';
        if (selected) {
            const selectedNode = findNode(treeData, selected);
            if (selectedNode) {
                parentPath = selectedNode.type === 'folder'
                    ? selectedNode.path
                    : selectedNode.path.substring(0, selectedNode.path.lastIndexOf('/'));
            }
        }

        const newPath = parentPath
            ? `${parentPath}${parentPath.endsWith('/') ? '' : '/'}${newItemName}`
            : newItemName;

        // Check if item already exists
        const exists = await checkFileExists(newPath);
        if (exists) {
            alert(`Item ${newPath} already exists!`);
            return;
        }

        try {
            if (newItemType === 'folder') {
                // Create directory
                await createDirectory(newPath);
                console.log(`Created directory: ${newPath}`);
            } else {
                // Create an empty file
                await writeFile(newPath, '');
                console.log(`Created empty file: ${newPath}`);
            }

            // Refresh the tree
            fetchDirectoryStructure();

            // Expand parent folder
            if (parentPath && !expanded.includes(parentPath)) {
                setExpanded([...expanded, parentPath]);
            }

            // Select the new item
            setSelected(newPath);
        } catch (error) {
            console.error(`Failed to create ${newItemType}:`, error);
            alert(`Failed to create ${newItemType}: ${error.message || 'Unknown error'}`);
        }

        setIsCreatingNew(false);
    };

    const handleDeleteItem = async () => {
        if (!selected) return;

        // Find the selected node
        const selectedNode = findNode(treeData, selected);
        if (!selectedNode) return;

        const isFolder = selectedNode.type === 'folder';
        const confirmMessage = isFolder
            ? `Delete folder "${selectedNode.name}" and all its contents?`
            : `Delete file "${selectedNode.name}"?`;

        if (!window.confirm(confirmMessage)) return;

        try {
            await deleteFile(selectedNode.path);
            console.log(`Deleted ${selectedNode.type}: ${selectedNode.path}`);

            // Refresh the tree
            fetchDirectoryStructure();

            // Clear selection
            setSelected('');
        } catch (error) {
            console.error(`Failed to delete ${selectedNode.type}:`, error);
            alert(`Failed to delete: ${error.message || 'Unknown error'}`);
        }
    };

    const handleLoadGitHubDirectory = async () => {
        if (!selected) return;

        // Find the selected node
        const selectedNode = findNode(treeData, selected);
        if (!selectedNode || selectedNode.type !== 'folder') {
            alert('Please select a folder to load from GitHub');
            return;
        }

        try {
            const result = await loadGitHubDirectory(selectedNode.path, true);
            console.log(`Loaded ${result.successful_files} files from GitHub`);

            // Refresh the tree
            fetchDirectoryStructure();

            alert(`Successfully loaded ${result.successful_files} files from GitHub.`);
        } catch (error) {
            console.error(`Failed to load GitHub directory:`, error);
            alert(`Failed to load from GitHub: ${error.message || 'Unknown error'}`);
        }
    };

    const handleViewAttributes = async () => {
        if (!selected) return;

        // Find the selected node
        const selectedNode = findNode(treeData, selected);
        if (!selectedNode) return;

        try {
            // Fetch latest attributes
            const attributes = await getFileAttributes(selectedNode.path);

            if (attributes) {
                // Set selected node for attributes dialog
                setSelectedNodeForAttributes({
                    ...selectedNode,
                    attributes
                });

                // Open dialog
                setAttributesDialogOpen(true);
            }
        } catch (error) {
            console.error(`Failed to get attributes:`, error);
            alert(`Failed to get attributes: ${error.message || 'Unknown error'}`);
        }
    };

    // Find a node by ID recursively
    const findNode = (nodes: TreeNode[], id: string): TreeNode | null => {
        for (const node of nodes) {
            if (node.id === id) return node;
            if (node.children) {
                const found = findNode(node.children, id);
                if (found) return found;
            }
        }
        return null;
    };

    // Render TreeItems recursively
    const renderTree = (nodes: TreeNode[]) => {
        return nodes.map((node) => (
            <TreeItem
                key={node.id}
                nodeId={node.id}
                label={
                    <Box sx={{ display: 'flex', alignItems: 'center', py: 0.5 }}>
                        <Box sx={{ mr: 1, display: 'flex', alignItems: 'center' }}>
                            {node.type === 'folder' ? (
                                expanded.includes(node.id) ? (
                                    <FolderOpenIcon color="primary" fontSize="small" />
                                ) : (
                                    <FolderIcon fontSize="small" />
                                )
                            ) : (
                                <InsertDriveFileIcon fontSize="small" />
                            )}
                        </Box>
                        <Box sx={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            width: '100%',
                            overflow: 'hidden'
                        }}>
                            <Tooltip title={node.path} placement="top">
                                <Typography
                                    variant="body2"
                                    noWrap
                                    sx={{
                                        maxWidth: '200px',
                                        ...(node.isPlaceholder && {
                                            fontStyle: 'italic',
                                            color: 'text.secondary'
                                        })
                                    }}
                                >
                                    {node.name}
                                    {node.isPlaceholder && ' (placeholder)'}
                                </Typography>
                            </Tooltip>

                            {node.attributes && node.type === 'file' && (
                                <Typography
                                    variant="caption"
                                    color="text.secondary"
                                    sx={{ ml: 2, flexShrink: 0 }}
                                >
                                    {formatFileSize(node.attributes.size)}
                                </Typography>
                            )}
                        </Box>
                    </Box>
                }
            >
                {node.children && node.children.length > 0 ? renderTree(node.children) : null}
            </TreeItem>
        ));
    };

    return (
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            {/* Toolbar */}
            <Box sx={{ p: 1, borderBottom: '1px solid #eee', display: 'flex', justifyContent: 'space-between' }}>
                <Typography variant="subtitle1">Files</Typography>
                <Box>
                    <Tooltip title="New folder">
                        <IconButton
                            size="small"
                            onClick={() => {
                                setNewItemType('folder');
                                handleCreateNewItem();
                            }}
                        >
                            <CreateNewFolderIcon fontSize="small" />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="New file">
                        <IconButton
                            size="small"
                            onClick={() => {
                                setNewItemType('file');
                                handleCreateNewItem();
                            }}
                        >
                            <AddIcon fontSize="small" />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete selected">
                        <span>
                            <IconButton
                                size="small"
                                onClick={handleDeleteItem}
                                disabled={!selected}
                            >
                                <DeleteIcon fontSize="small" />
                            </IconButton>
                        </span>
                    </Tooltip>
                    <Tooltip title="View attributes">
                        <span>
                            <IconButton
                                size="small"
                                onClick={handleViewAttributes}
                                disabled={!selected}
                            >
                                <InsertDriveFileIcon fontSize="small" />
                            </IconButton>
                        </span>
                    </Tooltip>
                    <Tooltip title="Load from GitHub">
                        <span>
                            <IconButton
                                size="small"
                                onClick={handleLoadGitHubDirectory}
                                disabled={!selected || (selected && findNode(treeData, selected)?.type !== 'folder')}
                            >
                                <CloudUploadIcon fontSize="small" />
                            </IconButton>
                        </span>
                    </Tooltip>
                    <Tooltip title="Refresh">
                        <IconButton
                            size="small"
                            onClick={() => setRefreshTrigger(prev => prev + 1)}
                        >
                            <RefreshIcon fontSize="small" />
                        </IconButton>
                    </Tooltip>
                </Box>
            </Box>

            {/* New item form */}
            {isCreatingNew && (
                <Box sx={{ p: 1, borderBottom: '1px solid #eee' }}>
                    <TextField
                        fullWidth
                        size="small"
                        variant="outlined"
                        label={`New ${newItemType} name`}
                        value={newItemName}
                        onChange={(e) => setNewItemName(e.target.value)}
                        autoFocus
                        margin="dense"
                    />
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 1 }}>
                        <Button size="small" onClick={() => setIsCreatingNew(false)} sx={{ mr: 1 }}>
                            Cancel
                        </Button>
                        <Button
                            size="small"
                            variant="contained"
                            color="primary"
                            onClick={handleSaveNewItem}
                            disabled={!newItemName}
                            startIcon={newItemType === 'folder' ? <CreateNewFolderIcon /> : <AddIcon />}
                        >
                            Create
                        </Button>
                    </Box>
                </Box>
            )}

            {/* Tree view */}
            <Box sx={{ flexGrow: 1, overflow: 'auto', p: 1 }}>
                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        <CircularProgress size={24} />
                    </Box>
                ) : (
                    <ClientOnly>
                        <TreeView
                            aria-label="file system navigator"
                            defaultCollapseIcon={<ExpandMoreIcon />}
                            defaultExpandIcon={<ChevronRightIcon />}
                            expanded={expanded}
                            selected={selected}
                            onNodeToggle={handleToggle}
                            onNodeSelect={handleSelect}
                            sx={{
                                flexGrow: 1,
                                overflowY: 'auto',
                                '& .MuiTreeItem-root': {
                                    '&:hover': { bgcolor: 'rgba(0, 0, 0, 0.04)' },
                                    '&.Mui-selected': { bgcolor: 'rgba(25, 118, 210, 0.08)' }
                                }
                            }}
                        >
                            {renderTree(treeData)}
                        </TreeView>
                    </ClientOnly>
                )}
            </Box>

            {/* Attributes dialog */}
            <Dialog
                open={attributesDialogOpen}
                onClose={() => setAttributesDialogOpen(false)}
                maxWidth="xs"
                fullWidth
            >
                <DialogTitle>
                    {selectedNodeForAttributes?.name} Attributes
                </DialogTitle>
                <DialogContent dividers>
                    {selectedNodeForAttributes?.attributes && (
                        <Box sx={{ py: 1 }}>
                            <Typography variant="body2" gutterBottom>
                                <strong>Path:</strong> {selectedNodeForAttributes.path}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Type:</strong> {selectedNodeForAttributes.type}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Size:</strong> {formatFileSize(selectedNodeForAttributes.attributes.size)}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>MIME Type:</strong> {selectedNodeForAttributes.attributes.file_type}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Created:</strong> {new Date(selectedNodeForAttributes.attributes.created_at * 1000).toLocaleString()}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Modified:</strong> {new Date(selectedNodeForAttributes.attributes.modified_at * 1000).toLocaleString()}
                            </Typography>
                            {selectedNodeForAttributes.isPlaceholder && (
                                <Typography variant="body2" color="warning.main" gutterBottom>
                                    This is a placeholder file. Content will be loaded on first access.
                                </Typography>
                            )}
                        </Box>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setAttributesDialogOpen(false)}>
                        Close
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
} 