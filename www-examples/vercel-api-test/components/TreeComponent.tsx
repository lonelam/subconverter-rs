import React, { useEffect, useState } from 'react';
import { Box, Typography } from '@mui/material';
import TreeView from '@mui/lab/TreeView';
import TreeItem from '@mui/lab/TreeItem';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';

// TreeNode 类型定义
interface FileNode {
    id: string;
    name: string;
    type: 'file' | 'folder';
    path: string;
    data?: any;
    index: string;
    children?: string[];
    isFolder?: boolean;
}

// 属性接口
interface TreeComponentProps {
    treeData: Record<string, FileNode>;
    expandedItems: string[];
    selectedItems: string[];
    onExpand: (itemId: string) => void;
    onCollapse: (itemId: string) => void;
    onSelect: (itemIds: string[]) => void;
    renderItem: (node: FileNode) => React.ReactNode;
}

const TreeComponent: React.FC<TreeComponentProps> = ({
    treeData,
    expandedItems,
    selectedItems,
    onExpand,
    onCollapse,
    onSelect,
    renderItem
}) => {
    const [isReady, setIsReady] = useState(false);

    // 确保只在客户端执行
    useEffect(() => {
        setIsReady(true);
    }, []);

    // 处理节点展开/折叠
    const handleToggle = (event: React.SyntheticEvent, nodeIds: string[]) => {
        // 找出新增和移除的节点
        const newExpanded = new Set(nodeIds);
        const oldExpanded = new Set(expandedItems);

        // 找出新展开的节点
        for (const id of nodeIds) {
            if (!oldExpanded.has(id)) {
                onExpand(id);
            }
        }

        // 找出新折叠的节点
        for (const id of expandedItems) {
            if (!newExpanded.has(id)) {
                onCollapse(id);
            }
        }
    };

    // 处理节点选择
    const handleSelect = (event: React.SyntheticEvent, nodeId: string) => {
        onSelect([nodeId]);
    };

    // 递归渲染树节点
    const renderTree = (nodeId: string) => {
        const node = treeData[nodeId];
        if (!node) return null;

        return (
            <TreeItem
                key={node.id}
                nodeId={node.id}
                label={renderItem(node)}
            >
                {node.children && node.children.length > 0
                    ? node.children.map((childId) => renderTree(childId))
                    : null}
            </TreeItem>
        );
    };

    if (!isReady) {
        return <Box sx={{ p: 2, textAlign: 'center' }}>初始化树组件...</Box>;
    }

    return (
        <TreeView
            aria-label="file system navigator"
            defaultCollapseIcon={<ExpandMoreIcon />}
            defaultExpandIcon={<ChevronRightIcon />}
            expanded={expandedItems}
            selected={selectedItems[0] || ''}
            onNodeToggle={handleToggle}
            onNodeSelect={handleSelect}
            sx={{
                flexGrow: 1,
                overflowY: 'auto',
                padding: 1,
                '& .MuiTreeItem-root': {
                    '&:hover': { bgcolor: 'rgba(0, 0, 0, 0.04)' },
                    '&.Mui-selected': { bgcolor: 'rgba(25, 118, 210, 0.08)' }
                }
            }}
        >
            {renderTree('root')}
        </TreeView>
    );
};

export default TreeComponent; 