"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Folder,
  FolderOpen,
  File,
  ChevronRight,
  ChevronDown,
} from "lucide-react";

interface FileEntry {
  name: string;
  path: string;
  isDirectory: boolean;
  size?: number;
}

interface TreeNode extends FileEntry {
  children?: TreeNode[];
  expanded?: boolean;
  loaded?: boolean;
}

export function FileBrowser() {
  const [rootPath, setRootPath] = useState("/");
  const [pathParts, setPathParts] = useState<string[]>(["/"]);
  const [entries, setEntries] = useState<TreeNode[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [previewName, setPreviewName] = useState<string | null>(null);

  const fetchDirectory = useCallback(
    async (path: string): Promise<FileEntry[]> => {
      try {
        const res = await fetch(
          `/api/files?path=${encodeURIComponent(path)}`
        );
        if (!res.ok) return [];
        const data = await res.json();
        return data.entries ?? data;
      } catch {
        return [];
      }
    },
    []
  );

  const loadRoot = useCallback(
    async (path: string) => {
      setIsLoading(true);
      const items = await fetchDirectory(path);
      setEntries(
        items.map((e) => ({
          ...e,
          expanded: false,
          loaded: false,
          children: [],
        }))
      );
      setRootPath(path);

      // Build breadcrumb parts
      const parts = path === "/" ? ["/"] : ["/", ...path.split("/").filter(Boolean)];
      setPathParts(parts);

      setIsLoading(false);
      setPreviewContent(null);
      setPreviewName(null);
    },
    [fetchDirectory]
  );

  useEffect(() => {
    loadRoot("/");
  }, [loadRoot]);

  const toggleDirectory = useCallback(
    async (node: TreeNode, path: number[]) => {
      const updateNode = (
        nodes: TreeNode[],
        indices: number[]
      ): TreeNode[] => {
        const [head, ...rest] = indices;
        return nodes.map((n, i) => {
          if (i !== head) return n;
          if (rest.length === 0) return { ...n, expanded: !n.expanded };
          return {
            ...n,
            children: updateNode(n.children ?? [], rest),
          };
        });
      };

      // If not loaded yet, fetch children
      if (!node.loaded && node.isDirectory) {
        const children = await fetchDirectory(node.path);
        const setChildren = (
          nodes: TreeNode[],
          indices: number[]
        ): TreeNode[] => {
          const [head, ...rest] = indices;
          return nodes.map((n, i) => {
            if (i !== head) return n;
            if (rest.length === 0) {
              return {
                ...n,
                expanded: true,
                loaded: true,
                children: children.map((c) => ({
                  ...c,
                  expanded: false,
                  loaded: false,
                  children: [],
                })),
              };
            }
            return {
              ...n,
              children: setChildren(n.children ?? [], rest),
            };
          });
        };
        setEntries((prev) => setChildren(prev, path));
      } else {
        setEntries((prev) => updateNode(prev, path));
      }
    },
    [fetchDirectory]
  );

  const handleFileClick = useCallback(async (entry: FileEntry) => {
    try {
      const res = await fetch(
        `/api/files?path=${encodeURIComponent(entry.path)}&content=true`
      );
      if (!res.ok) {
        setPreviewContent("Failed to load file");
        setPreviewName(entry.name);
        return;
      }
      const data = await res.json();
      setPreviewContent(data.content ?? "");
      setPreviewName(entry.name);
    } catch {
      setPreviewContent("Failed to load file");
      setPreviewName(entry.name);
    }
  }, []);

  const navigateBreadcrumb = useCallback(
    (index: number) => {
      if (index === 0) {
        loadRoot("/");
      } else {
        const path = "/" + pathParts.slice(1, index + 1).join("/");
        loadRoot(path);
      }
    },
    [pathParts, loadRoot]
  );

  const renderTree = (nodes: TreeNode[], depth: number, basePath: number[]) => {
    return nodes.map((node, i) => {
      const currentPath = [...basePath, i];
      return (
        <div key={node.path}>
          <button
            className="w-full flex items-center gap-1 py-1 px-2 text-[13px]
              hover:bg-[#252838] transition-colors text-left"
            style={{ paddingLeft: `${8 + depth * 16}px` }}
            onClick={() => {
              if (node.isDirectory) {
                toggleDirectory(node, currentPath);
              } else {
                handleFileClick(node);
              }
            }}
          >
            {node.isDirectory ? (
              <>
                {node.expanded ? (
                  <ChevronDown size={12} className="text-[#6B7280] shrink-0" />
                ) : (
                  <ChevronRight size={12} className="text-[#6B7280] shrink-0" />
                )}
                {node.expanded ? (
                  <FolderOpen size={14} className="text-[#3B82F6] shrink-0" />
                ) : (
                  <Folder size={14} className="text-[#3B82F6] shrink-0" />
                )}
              </>
            ) : (
              <>
                <span className="w-3 shrink-0" />
                <File size={14} className="text-[#6B7280] shrink-0" />
              </>
            )}
            <span className="truncate text-[#E4E4E7]">{node.name}</span>
          </button>
          {node.isDirectory &&
            node.expanded &&
            node.children &&
            renderTree(node.children, depth + 1, currentPath)}
        </div>
      );
    });
  };

  return (
    <div className="flex flex-col h-full text-[13px] font-sans">
      {/* Breadcrumbs */}
      <div className="flex items-center gap-0.5 px-2 py-2 border-b border-[#2A2D3A] overflow-x-auto">
        {pathParts.map((part, i) => (
          <span key={i} className="flex items-center gap-0.5 whitespace-nowrap">
            {i > 0 && <span className="text-[#6B7280]">/</span>}
            <button
              onClick={() => navigateBreadcrumb(i)}
              className="text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
            >
              {part === "/" ? "~" : part}
            </button>
          </span>
        ))}
      </div>

      {/* File tree or preview */}
      {previewContent !== null ? (
        <div className="flex flex-col flex-1 overflow-hidden">
          <div className="flex items-center justify-between px-2 py-1.5 border-b border-[#2A2D3A] bg-[#1C1F2B]">
            <span className="text-[#E4E4E7] truncate">{previewName}</span>
            <button
              onClick={() => {
                setPreviewContent(null);
                setPreviewName(null);
              }}
              className="text-[#6B7280] hover:text-[#E4E4E7] transition-colors text-xs"
            >
              Close
            </button>
          </div>
          <pre className="flex-1 overflow-auto p-2 text-[12px] font-mono text-[#E4E4E7] leading-relaxed whitespace-pre">
            {previewContent}
          </pre>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto py-1">
          {isLoading ? (
            <div className="px-3 py-4 text-[#6B7280] text-center">
              Loading...
            </div>
          ) : entries.length === 0 ? (
            <div className="px-3 py-4 text-[#6B7280] text-center">
              Empty directory
            </div>
          ) : (
            renderTree(entries, 0, [])
          )}
        </div>
      )}
    </div>
  );
}
