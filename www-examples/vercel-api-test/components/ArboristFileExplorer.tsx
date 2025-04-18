import React, { useState, useEffect, useCallback } from 'react';
import { Box, Typography, IconButton, TextField, Button, Tooltip, Dialog, DialogTitle, DialogContent, DialogActions, CircularProgress, List, ListItem, ListItemIcon, ListItemText, Collapse } from '@mui/material';
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

// 文件节点类型定义
interface FileNode {
    id: string;
    name: string;
    type: 'file' | 'folder';
    data?: {
        path: string;
        attributes?: FileAttributes;
        isPlaceholder?: boolean;
    };
    children?: FileNode[];
    isOpen?: boolean;
}

interface ArboristFileExplorerProps {
    onFileSelect: (path: string) => void;
    rootPath?: string;
}

// 格式化文件大小
const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

export default function ArboristFileExplorer({ onFileSelect, rootPath = '' }: ArboristFileExplorerProps) {
    const [treeData, setTreeData] = useState<FileNode[]>([]);
    const [loading, setLoading] = useState(false);
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    const [isClient, setIsClient] = useState(false);
    const [selectedNode, setSelectedNode] = useState<FileNode | null>(null);
    const [expanded, setExpanded] = useState<string[]>([]);

    // 新项目创建状态
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [newItemName, setNewItemName] = useState('');
    const [newItemType, setNewItemType] = useState<'file' | 'folder'>('file');

    // 文件属性对话框状态
    const [attributesDialogOpen, setAttributesDialogOpen] = useState(false);
    const [selectedNodeForAttributes, setSelectedNodeForAttributes] = useState<FileNode | null>(null);

    // 确保只在客户端渲染
    useEffect(() => {
        setIsClient(true);
        // 默认展开根目录
        setExpanded(['root']);
    }, []);

    // 当数据加载完成后，确保根目录展开
    useEffect(() => {
        if (treeData.length > 0 && !expanded.includes('root')) {
            setExpanded(prev => [...prev, 'root']);
        }
    }, [treeData, expanded]);

    // 加载目录结构
    const fetchDirectoryStructure = async () => {
        setLoading(true);
        try {
            const response = await fetch('/api/admin/list');
            if (!response.ok) {
                throw new Error(`Failed to fetch directory structure: ${response.statusText}`);
            }
            const data = await response.json();

            console.log('API返回的原始数据:', data);

            // API已经返回了树形结构，所以我们需要调整格式以匹配我们的组件需要
            const adaptApiStructure = (structure: any[]): FileNode[] => {
                if (!structure || !Array.isArray(structure)) {
                    console.error('API返回的结构无效或为空');
                    return [];
                }

                // 创建根节点
                const rootNode: FileNode = {
                    id: 'root',
                    name: 'Root',
                    type: 'folder',
                    data: { path: '' },
                    children: []
                };

                // 递归转换节点的函数
                const convertNode = (apiNode: any): FileNode => {
                    return {
                        id: apiNode.id,
                        name: apiNode.name,
                        type: apiNode.type,
                        data: {
                            path: apiNode.id,
                            attributes: apiNode.attributes,
                            isPlaceholder: apiNode.isPlaceholder
                        },
                        children: apiNode.children ?
                            apiNode.children.map(convertNode) :
                            (apiNode.type === 'folder' ? [] : undefined)
                    };
                };

                // 转换所有根级节点
                rootNode.children = structure.map(convertNode);

                console.log('转换后的树结构:', [rootNode]);
                return [rootNode];
            };

            const tree = adaptApiStructure(data.structure || []);

            // 默认展开根节点
            setExpanded(['root']);
            setTreeData(tree);
        } catch (error) {
            console.error('Error fetching directory structure:', error);
            // 备用数据
            setTreeData([
                {
                    id: 'root',
                    name: 'Root',
                    type: 'folder',
                    data: { path: '' },
                    children: [
                        {
                            id: 'configs',
                            name: 'configs',
                            type: 'folder',
                            data: { path: 'configs' },
                            children: [
                                {
                                    id: 'configs/config.ini',
                                    name: 'config.ini',
                                    type: 'file',
                                    data: { path: 'configs/config.ini' }
                                }
                            ]
                        },
                        {
                            id: 'README.md',
                            name: 'README.md',
                            type: 'file',
                            data: { path: 'README.md' }
                        }
                    ]
                }
            ]);
            // 默认展开根节点
            setExpanded(['root']);
        } finally {
            setLoading(false);
        }
    };

    // 加载目录结构
    useEffect(() => {
        if (isClient) {
            fetchDirectoryStructure();
        }
    }, [refreshTrigger, isClient]);

    // 展开到特定路径的所有父文件夹
    const expandToPath = useCallback((path: string) => {
        if (!path) return;

        const pathParts: string[] = [];
        const segments = path.split('/');

        // 构建所有父路径
        for (let i = 0; i < segments.length; i++) {
            const currentPath = segments.slice(0, i + 1).join('/');
            if (currentPath) {
                pathParts.push(currentPath);
            }
        }

        // 添加根节点
        const expandedPaths = ['root', ...pathParts];
        console.log('展开路径:', expandedPaths);
        setExpanded(prev => [...new Set([...prev, ...expandedPaths])]);
    }, []);

    // 当选择文件时，自动展开到该文件的路径
    useEffect(() => {
        if (selectedNode?.data?.path) {
            const path = selectedNode.data.path;
            if (path.includes('/')) {
                const folderPath = path.substring(0, path.lastIndexOf('/'));
                expandToPath(folderPath);
            }
        }
    }, [selectedNode, expandToPath]);

    // 创建新项目
    const handleCreateNewItem = () => {
        setIsCreatingNew(true);
        setNewItemName('');
    };

    // 保存新项目
    const handleSaveNewItem = async () => {
        if (!newItemName) return;

        // 确定父路径
        let parentPath = '';
        if (selectedNode) {
            parentPath = selectedNode.type === 'folder'
                ? selectedNode.data!.path
                : selectedNode.data!.path.includes('/')
                    ? selectedNode.data!.path.substring(0, selectedNode.data!.path.lastIndexOf('/'))
                    : '';
        }

        const newPath = parentPath
            ? `${parentPath}${parentPath.endsWith('/') ? '' : '/'}${newItemName}`
            : newItemName;

        // 检查项目是否已存在
        const exists = await checkFileExists(newPath);
        if (exists) {
            alert(`Item ${newPath} already exists!`);
            return;
        }

        try {
            if (newItemType === 'folder') {
                // 创建目录
                await createDirectory(newPath);
                console.log(`Created directory: ${newPath}`);
            } else {
                // 创建空文件
                await writeFile(newPath, '');
                console.log(`Created empty file: ${newPath}`);
            }

            // 刷新目录树
            setRefreshTrigger(prev => prev + 1);
        } catch (error) {
            console.error(`Failed to create ${newItemType}:`, error);
            alert(`Failed to create ${newItemType}: ${error.message || 'Unknown error'}`);
        }

        setIsCreatingNew(false);
    };

    // 删除项目
    const handleDeleteItem = async () => {
        if (!selectedNode) return;

        const isFolder = selectedNode.type === 'folder';
        const confirmMessage = isFolder
            ? `Delete folder "${selectedNode.name}" and all its contents?`
            : `Delete file "${selectedNode.name}"?`;

        if (!window.confirm(confirmMessage)) return;

        try {
            await deleteFile(selectedNode.data!.path);
            console.log(`Deleted ${selectedNode.type}: ${selectedNode.data!.path}`);

            // 刷新目录树
            setRefreshTrigger(prev => prev + 1);

            // 清除选择
            setSelectedNode(null);
        } catch (error) {
            console.error(`Failed to delete:`, error);
            alert(`Failed to delete: ${error.message || 'Unknown error'}`);
        }
    };

    // 从GitHub加载目录
    const handleLoadGitHubDirectory = async () => {
        if (!selectedNode || selectedNode.type !== 'folder') {
            alert('Please select a folder to load from GitHub');
            return;
        }

        try {
            const result = await loadGitHubDirectory(selectedNode.data!.path, true);
            console.log(`Loaded ${result.successful_files} files from GitHub`);

            // 刷新目录树
            setRefreshTrigger(prev => prev + 1);

            alert(`Successfully loaded ${result.successful_files} files from GitHub.`);
        } catch (error) {
            console.error(`Failed to load GitHub directory:`, error);
            alert(`Failed to load from GitHub: ${error.message || 'Unknown error'}`);
        }
    };

    // 查看文件属性
    const handleViewAttributes = async () => {
        if (!selectedNode) return;

        try {
            // 获取最新的属性
            const attributes = await getFileAttributes(selectedNode.data!.path);

            if (attributes) {
                // 设置选中节点的属性
                setSelectedNodeForAttributes({
                    ...selectedNode,
                    data: {
                        ...selectedNode.data!,
                        attributes
                    }
                });

                // 打开对话框
                setAttributesDialogOpen(true);
            }
        } catch (error) {
            console.error(`Failed to get attributes:`, error);
            alert(`Failed to get attributes: ${error.message || 'Unknown error'}`);
        }
    };

    // 递归渲染树节点
    const renderTree = (node: FileNode) => {
        const isFolder = node.type === 'folder';
        const attributes = node.data?.attributes;
        const isPlaceholder = node.data?.isPlaceholder;
        const isExpanded = expanded.includes(node.id);

        // 打印目前的渲染状态
        if (isFolder && node.children && node.children.length > 0) {
            console.log(`渲染文件夹: ${node.name}, ID: ${node.id}, 展开状态: ${isExpanded}, 子项数量: ${node.children.length}`);
            if (isExpanded) {
                console.log(`  子项列表: ${node.children.map(c => c.name).join(', ')}`);
            }
        }

        const handleNodeClick = (e: React.MouseEvent) => {
            e.stopPropagation();
            setSelectedNode(node);

            if (node.type === 'file') {
                onFileSelect(node.data!.path);
            } else {
                // 展开/折叠逻辑
                if (isExpanded) {
                    console.log(`折叠文件夹: ${node.id}`);
                    setExpanded(expanded.filter(id => id !== node.id && !id.startsWith(`${node.id}/`)));
                } else {
                    console.log(`展开文件夹: ${node.id}`);
                    setExpanded([...expanded, node.id]);
                }
            }
        };

        // 计算缩进
        const depth = node.id === 'root' ? 0 : node.id.split('/').length;
        const indentLevel = node.id === 'root' ? 0 : depth;

        return (
            <React.Fragment key={node.id}>
                <ListItem
                    onClick={handleNodeClick}
                    sx={{
                        position: 'relative',
                        bgcolor: selectedNode?.id === node.id ? 'rgba(25, 118, 210, 0.12)' : 'transparent',
                        pl: 1 + indentLevel * 2,
                        py: 0.5,
                        borderRadius: 1,
                        cursor: 'pointer',
                        '&:hover': {
                            bgcolor: 'rgba(0, 0, 0, 0.04)'
                        }
                    }}
                >
                    <ListItemIcon sx={{ minWidth: 36 }}>
                        {isFolder ? (
                            isExpanded ? <FolderOpenIcon color="primary" fontSize="small" /> : <FolderIcon fontSize="small" />
                        ) : (
                            <InsertDriveFileIcon fontSize="small" />
                        )}
                    </ListItemIcon>
                    <ListItemText
                        primary={
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <Tooltip title={node.data?.path || ''} placement="top">
                                    <Typography
                                        variant="body2"
                                        noWrap
                                        sx={{
                                            fontWeight: selectedNode?.id === node.id ? 500 : 400,
                                            ...(isPlaceholder && {
                                                fontStyle: 'italic',
                                                color: 'text.secondary'
                                            })
                                        }}
                                    >
                                        {node.name}
                                        {isPlaceholder && ' (placeholder)'}
                                    </Typography>
                                </Tooltip>
                                {isFolder && node.children && (
                                    <Typography
                                        variant="caption"
                                        color="text.secondary"
                                        sx={{ ml: 0.5 }}
                                    >
                                        ({node.children.length})
                                    </Typography>
                                )}
                            </Box>
                        }
                        secondary={
                            attributes && !isFolder ? (
                                <Typography
                                    variant="caption"
                                    color="text.secondary"
                                >
                                    {formatFileSize(attributes.size)}
                                </Typography>
                            ) : null
                        }
                    />
                    {isFolder && (
                        <Box
                            onClick={(e) => {
                                e.stopPropagation();
                                if (isExpanded) {
                                    setExpanded(expanded.filter(id => id !== node.id));
                                } else {
                                    setExpanded([...expanded, node.id]);
                                }
                            }}
                            sx={{
                                position: 'absolute',
                                right: 8,
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                width: 24,
                                height: 24,
                                borderRadius: '50%',
                                '&:hover': {
                                    bgcolor: 'rgba(0, 0, 0, 0.08)'
                                }
                            }}
                        >
                            {isExpanded ? <ExpandMoreIcon fontSize="small" /> : <ChevronRightIcon fontSize="small" />}
                        </Box>
                    )}
                </ListItem>
                {isFolder && node.children && (
                    <Collapse in={isExpanded} timeout="auto" unmountOnExit>
                        <List disablePadding>
                            {node.children.length > 0 ? (
                                node.children.map((child) => renderTree(child))
                            ) : (
                                <ListItem sx={{ pl: indentLevel * 2 + 4 }}>
                                    <Typography variant="caption" color="text.secondary">
                                        (空文件夹)
                                    </Typography>
                                </ListItem>
                            )}
                        </List>
                    </Collapse>
                )}
            </React.Fragment>
        );
    };

    return (
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            {/* 工具栏 */}
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
                    <Tooltip title="View attributes">
                        <span>
                            <IconButton
                                size="small"
                                onClick={handleViewAttributes}
                                disabled={!selectedNode}
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
                                disabled={!selectedNode || selectedNode.type !== 'folder'}
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
                    <Tooltip title="调试树结构">
                        <IconButton
                            size="small"
                            color="warning"
                            onClick={() => {
                                console.log("当前树结构:", JSON.stringify(treeData, null, 2));
                                console.log("已展开节点:", expanded);
                                alert("目录结构已输出到控制台，请打开开发者工具查看");
                            }}
                        >
                            <span style={{ fontSize: '10px' }}>Debug</span>
                        </IconButton>
                    </Tooltip>
                </Box>
            </Box>

            {/* 新项目表单 */}
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

            {/* 树视图 */}
            <Box sx={{ flexGrow: 1, overflow: 'auto', p: 1 }}>
                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        <CircularProgress size={24} />
                    </Box>
                ) : !isClient ? (
                    <Box sx={{ p: 2, textAlign: 'center' }}>Loading file tree...</Box>
                ) : (
                    <List sx={{ width: '100%', bgcolor: 'background.paper' }}>
                        {treeData.map(node => renderTree(node))}
                    </List>
                )}
            </Box>

            {/* 属性对话框 */}
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
                    {selectedNodeForAttributes?.data?.attributes && (
                        <Box sx={{ py: 1 }}>
                            <Typography variant="body2" gutterBottom>
                                <strong>Path:</strong> {selectedNodeForAttributes.data.path}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Type:</strong> {selectedNodeForAttributes.type}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Size:</strong> {formatFileSize(selectedNodeForAttributes.data.attributes.size)}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>MIME Type:</strong> {selectedNodeForAttributes.data.attributes.file_type}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Created:</strong> {new Date(selectedNodeForAttributes.data.attributes.created_at * 1000).toLocaleString()}
                            </Typography>
                            <Typography variant="body2" gutterBottom>
                                <strong>Modified:</strong> {new Date(selectedNodeForAttributes.data.attributes.modified_at * 1000).toLocaleString()}
                            </Typography>
                            {selectedNodeForAttributes.data.isPlaceholder && (
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