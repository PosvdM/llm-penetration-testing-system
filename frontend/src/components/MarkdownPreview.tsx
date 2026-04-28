import { Fragment, type ReactNode } from "react";

interface MarkdownPreviewProps {
  content: string;
}

interface ListItemNode {
  text: string;
  children: ListItemNode[];
}

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean);

  return tokens.map((token, index) => {
    const key = `${keyPrefix}-${index}`;
    if (token.startsWith("**") && token.endsWith("**")) {
      return <strong key={key}>{token.slice(2, -2)}</strong>;
    }
    if (token.startsWith("`") && token.endsWith("`")) {
      return <code key={key}>{token.slice(1, -1)}</code>;
    }
    return <Fragment key={key}>{token}</Fragment>;
  });
}

function countIndent(line: string): number {
  const match = line.match(/^(\s*)/);
  return match ? match[1].length : 0;
}

function parseList(lines: string[], startIndex: number, baseIndent: number): [ListItemNode[], number] {
  const items: ListItemNode[] = [];
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) {
      break;
    }

    const indent = countIndent(line);
    const match = line.match(/^\s*-\s+(.*)$/);
    if (!match || indent < baseIndent) {
      break;
    }
    if (indent > baseIndent) {
      const lastItem = items[items.length - 1];
      if (!lastItem) {
        break;
      }
      const [children, nextIndex] = parseList(lines, index, indent);
      lastItem.children.push(...children);
      index = nextIndex;
      continue;
    }

    items.push({ text: match[1], children: [] });
    index += 1;
  }

  return [items, index];
}

function renderList(items: ListItemNode[], keyPrefix: string): ReactNode {
  return (
    <ul className="markdown-list">
      {items.map((item, index) => (
        <li key={`${keyPrefix}-${index}`}>
          <span>{renderInline(item.text, `${keyPrefix}-${index}`)}</span>
          {item.children.length > 0 ? renderList(item.children, `${keyPrefix}-${index}-child`) : null}
        </li>
      ))}
    </ul>
  );
}

export function MarkdownPreview({ content }: MarkdownPreviewProps) {
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trim();

    if (!trimmed) {
      index += 1;
      continue;
    }

    if (trimmed.startsWith("```")) {
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trim().startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) {
        index += 1;
      }
      blocks.push(
        <pre className="markdown-code-block" key={`code-${blocks.length}`}>
          <code>{codeLines.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    const headingMatch = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      const headingText = headingMatch[2];
      const className = `markdown-heading markdown-heading-${level}`;

      if (level === 1) {
        blocks.push(
          <h1 className={className} key={`heading-${blocks.length}`}>
            {renderInline(headingText, `heading-${blocks.length}`)}
          </h1>,
        );
      } else if (level === 2) {
        blocks.push(
          <h2 className={className} key={`heading-${blocks.length}`}>
            {renderInline(headingText, `heading-${blocks.length}`)}
          </h2>,
        );
      } else if (level === 3) {
        blocks.push(
          <h3 className={className} key={`heading-${blocks.length}`}>
            {renderInline(headingText, `heading-${blocks.length}`)}
          </h3>,
        );
      } else {
        blocks.push(
          <h4 className={className} key={`heading-${blocks.length}`}>
            {renderInline(headingText, `heading-${blocks.length}`)}
          </h4>,
        );
      }
      index += 1;
      continue;
    }

    if (/^\s*-\s+/.test(line)) {
      const [items, nextIndex] = parseList(lines, index, countIndent(line));
      blocks.push(<div key={`list-${blocks.length}`}>{renderList(items, `list-${blocks.length}`)}</div>);
      index = nextIndex;
      continue;
    }

    const paragraphLines = [trimmed];
    index += 1;
    while (index < lines.length) {
      const next = lines[index].trim();
      if (!next || next.startsWith("#") || next.startsWith("- ") || next.startsWith("```")) {
        break;
      }
      paragraphLines.push(next);
      index += 1;
    }

    blocks.push(
      <p className="markdown-paragraph" key={`paragraph-${blocks.length}`}>
        {renderInline(paragraphLines.join(" "), `paragraph-${blocks.length}`)}
      </p>,
    );
  }

  return <div className="markdown-preview">{blocks}</div>;
}
