import React, { useState, useEffect, useMemo } from 'react';
import { Box, Typography, IconButton, TextField, Button, Tooltip, Dialog, DialogTitle, DialogContent, DialogActions, CircularProgress } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import CreateNewFolderIcon from '@mui/icons-material/CreateNewFolder';
import FolderIcon from '@mui/icons-material/Folder';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import RefreshIcon from '@mui/icons-material/Refresh';
import dynamic from 'next/dynamic';
import { checkFileExists, deleteFile, writeFile, getFileAttributes, createDirectory, FileAttributes, DirectoryEntry, loadGitHubDirectory } from '../lib/api-client';

// Types for our file tree (移动到动态导入前)
interface FileNode {
  id: string;
  name: string;
  type: 'file' | 'folder';
  path: string;
  data?: any;
  index: string;
  children?: string[];
  isFolder?: boolean;
  attributes?: FileAttributes;
  isPlaceholder?: boolean;
}

interface TreeFileExplorerProps {
  onFileSelect: (path: string) => void;
  rootPath?: string;
}

// 动态导入TreeComponent替代之前的导入方式
const TreeComponent = dynamic(
  () => import('./TreeComponent'),
  { ssr: false, loading: () => <Box sx={{ p: 2, textAlign: 'center' }}><CircularProgress size={24} /></Box> }
);

// Helper function to format file size
const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

export default function TreeFileExplorer({ onFileSelect, rootPath = '' }: TreeFileExplorerProps) {
  const [treeData, setTreeData] = useState<Record<string, FileNode>>({});
  const [expandedItems, setExpandedItems] = useState<string[]>([]);
  const [selectedItems, setSelectedItems] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [isClient, setIsClient] = useState(false);

  // New item creation state
  const [isCreatingNew, setIsCreatingNew] = useState(false);
  const [newItemName, setNewItemName] = useState('');
  const [newItemType, setNewItemType] = useState<'file' | 'folder'>('file');

  // File attribute dialog state
  const [attributesDialogOpen, setAttributesDialogOpen] = useState(false);
  const [selectedNodeForAttributes, setSelectedNodeForAttributes] = useState<FileNode | null>(null);

  // 添加检测客户端的钩子
  useEffect(() => {
    setIsClient(true);
  }, []);

  // Convert our backend data structure to react-complex-tree format
  const convertToTreeItems = (nodes: any[]): Record<string, FileNode> => {
    const items: Record<string, FileNode> = {
      root: {
        id: 'root',
        name: 'Root',
        type: 'folder' as const,
        path: '',
        data: {},
        index: 'root',
        children: [],
        isFolder: true
      }
    };

    // First pass - create all nodes
    nodes.forEach(node => {
      const id = node.id;
      items[id] = {
        id,
        name: node.name,
        type: node.type,
        path: node.id,
        data: {
          attributes: node.attributes,
          isPlaceholder: node.isPlaceholder
        },
        index: id,
        children: node.type === 'folder' ? [] : undefined,
        isFolder: node.type === 'folder'
      };
    });

    // Second pass - build tree structure
    nodes.forEach(node => {
      if (node.id === 'root') return;

      const parentPath = node.id.includes('/')
        ? node.id.substring(0, node.id.lastIndexOf('/'))
        : 'root';

      const parent = items[parentPath] || items.root;

      if (parent && parent.children) {
        parent.children.push(node.id);
      } else if (parentPath === '') {
        // Add to root if no parent found
        items.root.children!.push(node.id);
      }
    });

    return items;
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
      const treeItems = convertToTreeItems(data.structure || []);
      setTreeData(treeItems);

      // Expand root by default
      setExpandedItems(['root']);
    } catch (error) {
      console.error('Error fetching directory structure:', error);
      // Fallback data with correct type annotations
      const fallbackData: Record<string, FileNode> = {
        root: {
          id: 'root',
          name: 'Root',
          type: 'folder' as const,
          path: '',
          data: {},
          index: 'root',
          children: ['configs', 'README.md'],
          isFolder: true
        },
        configs: {
          id: 'configs',
          name: 'configs',
          type: 'folder' as const,
          path: 'configs',
          data: {},
          index: 'configs',
          children: ['configs/config.ini'],
          isFolder: true
        },
        'configs/config.ini': {
          id: 'configs/config.ini',
          name: 'config.ini',
          type: 'file' as const,
          path: 'configs/config.ini',
          data: {},
          index: 'configs/config.ini',
          isFolder: false
        },
        'README.md': {
          id: 'README.md',
          name: 'README.md',
          type: 'file' as const,
          path: 'README.md',
          data: {},
          index: 'README.md',
          isFolder: false
        }
      };
      setTreeData(fallbackData);
      setExpandedItems(['root']);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // 只在客户端运行
    if (isClient) {
      fetchDirectoryStructure();
    }
  }, [refreshTrigger, isClient]);

  const handleCreateNewItem = () => {
    setIsCreatingNew(true);
    setNewItemName('');
  };

  const handleSaveNewItem = async () => {
    if (!newItemName) return;

    // Get current selected item as parent, or use root
    const parentItem = selectedItems.length > 0
      ? treeData[selectedItems[0]]
      : treeData.root;

    if (!parentItem || parentItem.type !== 'folder') {
      alert('Please select a folder to create the new item in');
      return;
    }

    const parentPath = parentItem.id === 'root' ? '' : parentItem.path;
    const newPath = parentPath ? `${parentPath}/${newItemName}` : newItemName;

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

      // Get attributes
      const attributes = await getFileAttributes(newPath);

      // Add to tree data
      const newNode: FileNode = {
        id: newPath,
        name: newItemName,
        type: newItemType,
        path: newPath,
        data: { attributes },
        index: newPath,
        children: newItemType === 'folder' ? [] : undefined,
        isFolder: newItemType === 'folder'
      };

      setTreeData(prev => {
        // Add new node
        const updated = { ...prev, [newPath]: newNode };

        // Add to parent's children
        if (parentItem && parentItem.children) {
          updated[parentItem.index] = {
            ...parentItem,
            children: [...parentItem.children, newPath]
          };
        }

        return updated;
      });

      // Expand parent
      if (!expandedItems.includes(parentItem.index)) {
        setExpandedItems(prev => [...prev, parentItem.index]);
      }

      // Select the new item
      setSelectedItems([newPath]);
    } catch (error) {
      console.error(`Failed to create ${newItemType}:`, error);
      alert(`Failed to create ${newItemType}: ${error.message || 'Unknown error'}`);
    }

    setIsCreatingNew(false);
  };

  const handleDeleteItem = async () => {
    if (selectedItems.length === 0) return;

    const itemId = selectedItems[0];
    const node = treeData[itemId];

    if (!node) return;

    const isFolder = node.type === 'folder';
    const confirmMessage = isFolder
      ? `Delete folder "${node.name}" and all its contents?`
      : `Delete file "${node.name}"?`;

    if (!window.confirm(confirmMessage)) return;

    try {
      await deleteFile(node.path);
      console.log(`Deleted ${node.type}: ${node.path}`);

      // Update tree data by removing the node and updating its parent
      setTreeData(prev => {
        const updated = { ...prev };

        // Find parent and remove from children
        Object.values(updated).forEach(item => {
          if (item.children && item.children.includes(itemId)) {
            item.children = item.children.filter(childId => childId !== itemId);
          }
        });

        // Delete node and its children (if folder)
        const nodesToDelete = [itemId];

        if (isFolder) {
          // Recursively collect all children
          const collectChildren = (nodeId: string) => {
            const node = updated[nodeId];
            if (node && node.children) {
              node.children.forEach(childId => {
                nodesToDelete.push(childId);
                collectChildren(childId);
              });
            }
          };

          collectChildren(itemId);
        }

        // Remove all collected nodes
        nodesToDelete.forEach(id => {
          delete updated[id];
        });

        return updated;
      });

      // Clear selection
      setSelectedItems([]);
    } catch (error) {
      console.error(`Failed to delete ${node.type}:`, error);
      alert(`Failed to delete: ${error.message || 'Unknown error'}`);
    }
  };

  const handleLoadGitHubDirectory = async () => {
    if (selectedItems.length === 0) return;

    const itemId = selectedItems[0];
    const node = treeData[itemId];

    if (!node || node.type !== 'folder') {
      alert('Please select a folder to load from GitHub');
      return;
    }

    try {
      const result = await loadGitHubDirectory(node.path, true);
      console.log(`Loaded ${result.successful_files} files from GitHub`);

      // Refresh the tree to show new files
      setRefreshTrigger(prev => prev + 1);

      alert(`Successfully loaded ${result.successful_files} files from GitHub.`);
    } catch (error) {
      console.error(`Failed to load GitHub directory:`, error);
      alert(`Failed to load from GitHub: ${error.message || 'Unknown error'}`);
    }
  };

  const handleViewAttributes = async () => {
    if (selectedItems.length === 0) return;

    const itemId = selectedItems[0];
    const node = treeData[itemId];

    if (!node) return;

    try {
      // Fetch latest attributes
      const attributes = await getFileAttributes(node.path);

      if (attributes) {
        // Update node with attributes
        setTreeData(prev => ({
          ...prev,
          [itemId]: {
            ...prev[itemId],
            data: {
              ...prev[itemId].data,
              attributes
            }
          }
        }));

        // Set selected node for attributes dialog
        setSelectedNodeForAttributes({
          ...node,
          data: {
            ...node.data,
            attributes
          }
        });

        // Open dialog
        setAttributesDialogOpen(true);
      }
    } catch (error) {
      console.error(`Failed to get attributes:`, error);
      alert(`Failed to get attributes: ${error.message || 'Unknown error'}`);
    }
  };

  // 自定义渲染树项的函数
  const renderItem = (node: FileNode) => {
    const isFolder = node.type === 'folder';
    const attributes = node.data?.attributes;
    const isPlaceholder = node.data?.isPlaceholder;

    return (
      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
        <Box sx={{ mr: 1, display: 'flex', alignItems: 'center' }}>
          {isFolder ? (
            expandedItems.includes(node.index) ? (
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

          {attributes && !isFolder && (
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ ml: 2, flexShrink: 0 }}
            >
              {formatFileSize(attributes.size)}
            </Typography>
          )}
        </Box>
      </Box>
    );
  };

  // 树渲染的回调函数
  const handleExpand = (itemId: string) => {
    setExpandedItems(prev => [...prev, itemId]);
  };

  const handleCollapse = (itemId: string) => {
    setExpandedItems(prev => prev.filter(id => id !== itemId));
  };

  const handleSelect = (itemIds: string[]) => {
    setSelectedItems(itemIds);

    // 处理文件选择
    if (itemIds.length === 1) {
      const selectedNode = treeData[itemIds[0]];
      if (selectedNode && selectedNode.type === 'file') {
        onFileSelect(selectedNode.path);
      }
    }
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
                disabled={selectedItems.length === 0}
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
                disabled={selectedItems.length === 0}
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
                disabled={selectedItems.length === 0 ||
                  (selectedItems.length > 0 && treeData[selectedItems[0]]?.type !== 'folder')}
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
      <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
        {loading ? (
          <Box sx={{ p: 2, textAlign: 'center' }}>
            <CircularProgress size={24} />
          </Box>
        ) : !isClient ? (
          // 服务端渲染时显示加载中
          <Box sx={{ p: 2, textAlign: 'center' }}>Loading file tree...</Box>
        ) : (
          <TreeComponent
            treeData={treeData}
            expandedItems={expandedItems}
            selectedItems={selectedItems}
            onExpand={handleExpand}
            onCollapse={handleCollapse}
            onSelect={handleSelect}
            renderItem={renderItem}
          />
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
          {selectedNodeForAttributes?.data?.attributes && (
            <Box sx={{ py: 1 }}>
              <Typography variant="body2" gutterBottom>
                <strong>Path:</strong> {selectedNodeForAttributes.path}
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