"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

interface MarkdownContentProps {
  content: string;
  className?: string;
}

/**
 * Renders markdown content with proper styling for threat intelligence reports.
 * Supports: headings, bullet lists, bold/italic, links, tables, code blocks.
 */
export default function MarkdownContent({ content, className = "" }: MarkdownContentProps) {
  return (
    <div className={`prose-intelwatch text-sm text-muted-foreground ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          // Headings
          h1: ({ children }) => (
            <h3 className="text-base font-semibold text-foreground mt-4 mb-2">{children}</h3>
          ),
          h2: ({ children }) => (
            <h4 className="text-sm font-semibold text-foreground mt-3 mb-1.5">{children}</h4>
          ),
          h3: ({ children }) => (
            <h5 className="text-sm font-medium text-foreground mt-2 mb-1">{children}</h5>
          ),
          // Paragraphs
          p: ({ children }) => <p className="mb-2 leading-relaxed">{children}</p>,
          // Lists
          ul: ({ children }) => (
            <ul className="list-disc list-outside ml-4 mb-2 space-y-0.5">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal list-outside ml-4 mb-2 space-y-0.5">{children}</ol>
          ),
          li: ({ children }) => <li className="leading-relaxed">{children}</li>,
          // Bold / italic
          strong: ({ children }) => (
            <strong className="font-semibold text-foreground">{children}</strong>
          ),
          em: ({ children }) => <em className="italic text-muted-foreground">{children}</em>,
          // Links
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline break-all"
            >
              {children}
            </a>
          ),
          // Code
          code: ({ children, className: codeClass }) => {
            const isBlock = codeClass?.includes("language-");
            if (isBlock) {
              return (
                <pre className="bg-muted/30 border border-border/30 rounded-md p-3 text-xs overflow-x-auto my-2">
                  <code>{children}</code>
                </pre>
              );
            }
            return (
              <code className="bg-muted/30 px-1 py-0.5 rounded text-xs font-mono text-primary/90">
                {children}
              </code>
            );
          },
          pre: ({ children }) => <>{children}</>,
          // Tables
          table: ({ children }) => (
            <div className="overflow-x-auto my-2">
              <table className="w-full text-xs border-collapse border border-border/30">{children}</table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="bg-muted/20">{children}</thead>
          ),
          th: ({ children }) => (
            <th className="border border-border/30 px-2 py-1.5 text-left font-medium text-foreground">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="border border-border/30 px-2 py-1.5">{children}</td>
          ),
          tr: ({ children }) => <tr className="hover:bg-muted/10">{children}</tr>,
          // Horizontal rule
          hr: () => <hr className="border-border/30 my-3" />,
          // Blockquote
          blockquote: ({ children }) => (
            <blockquote className="border-l-2 border-primary/30 pl-3 my-2 text-muted-foreground/80 italic">
              {children}
            </blockquote>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
