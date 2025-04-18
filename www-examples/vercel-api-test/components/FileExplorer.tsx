import React, { useState, useEffect } from 'react';
import { Box, Typography, IconButton, TextField, Button, List, ListItem, ListItemIcon, ListItemText, Collapse, Tooltip, Menu, MenuItem, Chip, ListItemSecondaryAction } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import CreateNewFolderIcon from '@mui/icons-material/CreateNewFolder';
import FolderIcon from '@mui/icons-material/Folder';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import { checkFileExists, deleteFile, writeFile, getFileAttributes, createDirectory, FileAttributes, DirectoryEntry, loadGitHubDirectory } from '../lib/api-client';

// Types for our file tree
interface TreeNode {
    id: string;
    name: string;
    type: 'file' | 'folder';
    children?: TreeNode[];
    attributes?: FileAttributes;
    isPlaceholder?: boolean;
}

interface FileExplorerProps {
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

// Helper function to format timestamp
const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
};

// Helper to get file icon based on type
const getFileIcon = (fileType: string): React.ReactNode => {
    // Basic mapping of mime types to icons
    // You could expand this with more specific icons
    switch (fileType) {
        case 'text/plain':
            return <InsertDriveFileIcon />;
        case 'application/json':
            return <InsertDriveFileIcon color="info" />;
        case 'text/markdown':
            return <InsertDriveFileIcon color="secondary" />;
        default:
            return <InsertDriveFileIcon />;
    }
};

export default function FileExplorer({ onFileSelect, rootPath = '' }: FileExplorerProps) {
    const [treeData, setTreeData] = useState<TreeNode[]>([]);
    const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({});
    const [newItemName, setNewItemName] = useState('');
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);
    const [newItemType, setNewItemType] = useState<'file' | 'folder'>('file');
    const [loading, setLoading] = useState(false);
    const [contextMenu, setContextMenu] = useState<{
        mouseX: number;
        mouseY: number;
        nodeId: string;
    } | null>(null);
    const [showAttributes, setShowAttributes] = useState<string | null>(null);

    // Fetch directory structure
    useEffect(() => {
        const fetchDirectoryStructure = async () => {
            setLoading(true);
            try {
                const response = await fetch('/api/admin/list');
                if (!response.ok) {
                    throw new Error(`Failed to fetch directory structure: ${response.statusText}`);
                }
                const data = await response.json();
                setTreeData(data.structure || []);

                // Auto-expand first level folders
                const newExpanded: Record<string, boolean> = {};
                data.structure.forEach((node: TreeNode) => {
                    if (node.type === 'folder') {
                        newExpanded[node.id] = true;
                    }
                });
                setExpandedNodes(newExpanded);
            } catch (error) {
                console.error('Error fetching directory structure:', error);
                // Fallback to dummy data if API fails
                const dummyData: TreeNode[] = [
                    {
                        id: 'configs',
                        name: 'configs',
                        type: 'folder',
                        children: [
                            { id: 'configs/config.ini', name: 'config.ini', type: 'file' },
                        ],
                    },
                    { id: 'README.md', name: 'README.md', type: 'file' },
                ];
                setTreeData(dummyData);
                setExpandedNodes({ configs: true });
            } finally {
                setLoading(false);
            }
        };

        fetchDirectoryStructure();
    }, []);

    const handleNodeSelect = (nodeId: string) => {
        setSelectedNode(nodeId);
        const node = findNodeById(treeData, nodeId);

        if (node && node.type === 'file') {
            onFileSelect(node.id);
        } else if (node && node.type === 'folder') {
            // Toggle folder expansion
            setExpandedNodes(prev => ({
                ...prev,
                [nodeId]: !prev[nodeId]
            }));
        }
    };

    const handleCreateNewItem = () => {
        setIsCreatingNew(true);
        setNewItemName('');
    };

    const handleSaveNewItem = async () => {
        if (!newItemName) return;

        // Determine the parent path
        let parentPath = '';
        if (selectedNode && selectedNode.includes('/')) {
            // If we have a selected node that's a nested path,
            // check if it's a file (remove filename) or folder (use as is)
            const node = findNodeById(treeData, selectedNode);
            if (node?.type === 'file') {
                parentPath = selectedNode.substring(0, selectedNode.lastIndexOf('/'));
            } else {
                parentPath = selectedNode;
            }
        }

        const newPath = parentPath ? `${parentPath}/${newItemName}` : newItemName;

        // Check if item already exists
        const exists = await checkFileExists(newPath);
        if (exists) {
            alert(`Item ${newPath} already exists!`);
            return;
        }

        try {
            if (newItemType === 'folder') {
                // Create directory via API
                await createDirectory(newPath);
                console.log(`Created directory: ${newPath}`);
            } else {
                // Create an empty file
                await writeFile(newPath, '');
                console.log(`Created empty file: ${newPath}`);
            }

            // Create a new node with attributes
            const attributes = await getFileAttributes(newPath);
            const newNode: TreeNode = {
                id: newPath,
                name: newItemName,
                type: newItemType,
                children: newItemType === 'folder' ? [] : undefined,
                attributes: attributes || undefined
            };

            // Add the new node to the tree
            if (!parentPath) {
                // Add to root
                setTreeData([...treeData, newNode]);
            } else {
                // Add to parent folder
                const updatedTree = addNodeToParent(treeData, parentPath, newNode);
                setTreeData(updatedTree);
            }

            if (newItemType === 'folder') {
                setExpandedNodes(prev => ({
                    ...prev,
                    [newPath]: true
                }));
            }
        } catch (error) {
            console.error(`Failed to create ${newItemType} ${newPath}:`, error);
            alert(`Failed to create ${newItemType}: ${error.message || 'Unknown error'}`);
        }

        setIsCreatingNew(false);
    };

    const handleCancelNewItem = () => {
        setIsCreatingNew(false);
    };

    const findNodeById = (nodes: TreeNode[], id: string): TreeNode | null => {
        for (const node of nodes) {
            if (node.id === id) return node;
            if (node.children) {
                const found = findNodeById(node.children, id);
                if (found) return found;
            }
        }
        return null;
    };

    const addNodeToParent = (nodes: TreeNode[], parentId: string, newNode: TreeNode): TreeNode[] => {
        return nodes.map(node => {
            if (node.id === parentId && node.type === 'folder') {
                return {
                    ...node,
                    children: [...(node.children || []), newNode],
                };
            } else if (node.children) {
                return {
                    ...node,
                    children: addNodeToParent(node.children, parentId, newNode),
                };
            }
            return node;
        });
    };

    const handleDeleteItem = async () => {
        if (!selectedNode) return;

        const node = findNodeById(treeData, selectedNode);
        if (!node) return;

        if (node.type === 'folder' && node.children && node.children.length > 0) {
            const confirm = window.confirm(`Delete folder ${node.name} and all its contents?`);
            if (!confirm) return;
        } else {
            const confirm = window.confirm(`Delete ${node.type} ${node.name}?`);
            if (!confirm) return;
        }

        try {
            // Delete the file or directory via API
            await deleteFile(node.id);
            console.log(`Deleted ${node.type}: ${node.id}`);

            // Remove the node from the tree
            const removeNode = (nodes: TreeNode[]): TreeNode[] => {
                return nodes.filter(n => {
                    if (n.id === node.id) return false;
                    if (n.children) {
                        n.children = removeNode(n.children);
                    }
                    return true;
                });
            };

            setTreeData(removeNode(treeData));
            setSelectedNode(null);
        } catch (error) {
            console.error(`Failed to delete ${node.type} ${node.id}:`, error);
            alert(`Failed to delete: ${error.message || 'Unknown error'}`);
        }
    };

    const handleContextMenu = (event: React.MouseEvent, nodeId: string) => {
        event.preventDefault();
        event.stopPropagation();
        setContextMenu({
            mouseX: event.clientX,
            mouseY: event.clientY,
            nodeId
        });
    };

    const handleCloseContextMenu = () => {
        setContextMenu(null);
    };

    const handleViewAttributes = async () => {
        if (contextMenu) {
            const nodeId = contextMenu.nodeId;
            setShowAttributes(nodeId === showAttributes ? null : nodeId);
            handleCloseContextMenu();

            // Fetch and update attributes when viewing
            if (nodeId !== showAttributes) {
                try {
                    const attributes = await getFileAttributes(nodeId);
                    if (attributes) {
                        // Update node with attributes
                        const updatedTree = updateNodeAttributes(treeData, nodeId, attributes);
                        setTreeData(updatedTree);
                    }
                } catch (error) {
                    console.error(`Failed to get attributes for ${nodeId}:`, error);
                }
            }
        }
    };

    const updateNodeAttributes = (
        nodes: TreeNode[],
        nodeId: string,
        attributes: FileAttributes
    ): TreeNode[] => {
        return nodes.map(node => {
            if (node.id === nodeId) {
                return {
                    ...node,
                    attributes
                };
            } else if (node.children) {
                return {
                    ...node,
                    children: updateNodeAttributes(node.children, nodeId, attributes)
                };
            }
            return node;
        });
    };

    // Add a function to load GitHub directory
    const handleLoadGitHubDirectory = async () => {
        if (contextMenu) {
            const nodeId = contextMenu.nodeId;
            const node = findNodeById(treeData, nodeId);

            if (node && node.type === 'folder') {
                try {
                    const result = await loadGitHubDirectory(nodeId, true);
                    console.log(`Loaded ${result.successful_files} files from GitHub`);

                    // Refresh the directory to show new files
                    const dirEntries = await fetch(`/api/admin/list?path=${encodeURIComponent(nodeId)}`);
                    const directoryData = await dirEntries.json();

                    // Update the tree with new directory contents
                    if (directoryData.entries) {
                        const updatedTree = updateDirectoryContents(treeData, nodeId, directoryData.entries);
                        setTreeData(updatedTree);
                    }

                    // Mark placeholder files
                    const updatedTreeWithPlaceholders = markPlaceholderFiles(
                        treeData,
                        result.loaded_files.filter(f => f.is_placeholder).map(f => f.path)
                    );
                    setTreeData(updatedTreeWithPlaceholders);
                } catch (error) {
                    console.error(`Failed to load GitHub directory ${nodeId}:`, error);
                }
            }
        }
        handleCloseContextMenu();
    };

    // Function to update directory contents
    const updateDirectoryContents = (
        nodes: TreeNode[],
        directoryId: string,
        newEntries: DirectoryEntry[]
    ): TreeNode[] => {
        return nodes.map(node => {
            if (node.id === directoryId && node.type === 'folder') {
                // Convert directory entries to tree nodes
                const childNodes: TreeNode[] = newEntries.map(entry => ({
                    id: entry.path,
                    name: entry.name,
                    type: entry.is_directory ? 'folder' : 'file',
                    children: entry.is_directory ? [] : undefined,
                    attributes: entry.attributes,
                    isPlaceholder: false
                }));

                return {
                    ...node,
                    children: childNodes
                };
            } else if (node.children) {
                return {
                    ...node,
                    children: updateDirectoryContents(node.children, directoryId, newEntries)
                };
            }
            return node;
        });
    };

    // Function to mark placeholder files in the tree
    const markPlaceholderFiles = (
        nodes: TreeNode[],
        placeholderPaths: string[]
    ): TreeNode[] => {
        return nodes.map(node => {
            if (placeholderPaths.includes(node.id)) {
                return {
                    ...node,
                    isPlaceholder: true
                };
            } else if (node.children) {
                return {
                    ...node,
                    children: markPlaceholderFiles(node.children, placeholderPaths)
                };
            }
            return node;
        });
    };

    const renderTreeNodes = (nodes: TreeNode[], level = 0) => {
        return nodes.map((node) => {
            const isFolder = node.type === 'folder';
            const isExpanded = expandedNodes[node.id] || false;

            return (
                <React.Fragment key={node.id}>
                    <ListItem
                        component="div"
                        onClick={() => handleNodeSelect(node.id)}
                        sx={{
                            pl: level * 2 + 1,
                            py: 0.5,
                            borderLeft: showAttributes === node.id ? '2px solid #2196f3' : 'none',
                            bgcolor: selectedNode === node.id ? 'action.selected' : 'transparent',
                            '&:hover': {
                                bgcolor: 'action.hover',
                            },
                            cursor: 'pointer',
                        }}
                        onContextMenu={(e) => handleContextMenu(e, node.id)}
                    >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                            {isFolder ? (
                                isExpanded ? <FolderOpenIcon color="primary" /> : <FolderIcon />
                            ) : node.attributes?.file_type ?
                                getFileIcon(node.attributes.file_type) :
                                <InsertDriveFileIcon />
                            }
                        </ListItemIcon>
                        <ListItemText
                            primary={
                                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                    <Tooltip title={node.id} placement="top">
                                        <Typography variant="body2" noWrap sx={{ mr: 1 }}>{node.name}</Typography>
                                    </Tooltip>
                                    {node.isPlaceholder && (
                                        <Chip
                                            label="Placeholder"
                                            size="small"
                                            color="warning"
                                            variant="outlined"
                                            sx={{ height: 20, fontSize: '0.6rem' }}
                                        />
                                    )}
                                    {node.attributes?.is_directory && (
                                        <Chip
                                            label="Dir"
                                            size="small"
                                            color="primary"
                                            variant="outlined"
                                            sx={{ height: 20, fontSize: '0.6rem', ml: 0.5 }}
                                        />
                                    )}
                                </Box>
                            }
                            secondary={
                                node.attributes && !isFolder ?
                                    <Typography variant="caption" color="text.secondary">
                                        {formatFileSize(node.attributes.size)}
                                    </Typography> :
                                    null
                            }
                        />
                        {isFolder && (
                            <ListItemIcon sx={{ minWidth: 24 }}>
                                {isExpanded ? <ExpandMoreIcon fontSize="small" /> : <ChevronRightIcon fontSize="small" />}
                            </ListItemIcon>
                        )}
                    </ListItem>

                    {showAttributes === node.id && node.attributes && (
                        <Box
                            sx={{
                                pl: level * 2 + 6,
                                py: 1,
                                bgcolor: 'action.hover',
                                borderLeft: '2px solid #2196f3',
                                fontSize: '0.75rem',
                            }}
                        >
                            <Typography variant="caption" display="block">
                                <strong>Size:</strong> {formatFileSize(node.attributes.size)}
                            </Typography>
                            <Typography variant="caption" display="block">
                                <strong>Type:</strong> {node.attributes.file_type}
                            </Typography>
                            <Typography variant="caption" display="block">
                                <strong>Created:</strong> {formatTimestamp(node.attributes.created_at)}
                            </Typography>
                            <Typography variant="caption" display="block">
                                <strong>Modified:</strong> {formatTimestamp(node.attributes.modified_at)}
                            </Typography>
                        </Box>
                    )}

                    {isFolder && node.children && (
                        <Collapse in={isExpanded} timeout="auto" unmountOnExit>
                            <List component="div" disablePadding>
                                {renderTreeNodes(node.children, level + 1)}
                            </List>
                        </Collapse>
                    )}
                </React.Fragment>
            );
        });
    };

    return (
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
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
                                disabled={!selectedNode}
                            >
                                <DeleteIcon fontSize="small" />
                            </IconButton>
                        </span>
                    </Tooltip>
                </Box>
            </Box>

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
                        <Button size="small" onClick={handleCancelNewItem} sx={{ mr: 1 }}>
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

            <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
                {loading ? (
                    <Box sx={{ p: 2, textAlign: 'center' }}>Loading...</Box>
                ) : (
                    <List dense component="nav">
                        {renderTreeNodes(treeData)}
                    </List>
                )}
            </Box>

            <Menu
                open={contextMenu !== null}
                onClose={handleCloseContextMenu}
                anchorReference="anchorPosition"
                anchorPosition={
                    contextMenu !== null
                        ? { top: contextMenu.mouseY, left: contextMenu.mouseX }
                        : undefined
                }
            >
                <MenuItem onClick={handleViewAttributes}>View Attributes</MenuItem>
                {contextMenu && findNodeById(treeData, contextMenu.nodeId)?.type === 'folder' && (
                    <MenuItem onClick={handleLoadGitHubDirectory}>Load from GitHub</MenuItem>
                )}
                <MenuItem onClick={() => {
                    if (contextMenu) {
                        setSelectedNode(contextMenu.nodeId);
                        handleDeleteItem();
                        handleCloseContextMenu();
                    }
                }}>Delete</MenuItem>
            </Menu>
        </Box>
    );
} 