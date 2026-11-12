// Renders an author-supplied README as Markdown, safely. react-markdown builds
// React elements (no dangerouslySetInnerHTML) and, without rehype-raw, treats
// raw HTML as plain text, so <script>, <iframe>, inline styles and event
// handlers cannot appear as markup. On top of that:
//   - links keep only http:, https: and mailto: (safeUrl), and get
//     rel="nofollow noopener noreferrer";
//   - images are never loaded: each becomes a text link to the image URL;
//   - headings are demoted so the page keeps its own h1 and h2.
import type { ComponentProps, ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import type { Components, Options } from "react-markdown";
import { capReadme, safeUrl } from "./markdown";
import { clean } from "./text";

const REL = "nofollow noopener noreferrer";
const LINK = "break-words text-blue-700 underline underline-offset-2 dark:text-blue-300";

type HNode = { type: string; tagName?: string; properties?: Record<string, unknown>; children?: HNode[] };

// A linked image would put an anchor inside an anchor; inside a link, the
// image is reduced to its alt text.
function flattenLinkedImages() {
  const walk = (node: HNode, inLink: boolean) => {
    if (!node.children) return;
    node.children = node.children.map((child) => {
      if (child.type === "element" && child.tagName === "img" && inLink) {
        const alt = child.properties?.alt;
        return { type: "text", value: `[image: ${typeof alt === "string" && alt ? alt : "image"}]` } as HNode;
      }
      walk(child, inLink || (child.type === "element" && child.tagName === "a"));
      return child;
    });
  };
  return (tree: HNode) => walk(tree, false);
}

const heading = (Tag: "h3" | "h4" | "h5" | "h6", cls: string) =>
  function H({ children }: { children?: ReactNode }) {
    return <Tag className={cls}>{children}</Tag>;
  };

const components: Components = {
  a({ href, children }: ComponentProps<"a">) {
    const h = safeUrl(href);
    return h ? (
      <a href={h} rel={REL} className={LINK}>
        {children}
      </a>
    ) : (
      <span>{children}</span>
    );
  },
  img({ src, alt }: ComponentProps<"img">) {
    const h = safeUrl(typeof src === "string" ? src : undefined);
    const text = clean(alt);
    if (!h) return <span>{`[image${text ? `: ${text}` : ""}]`}</span>;
    return (
      <a href={h} rel={REL} className={LINK}>
        {`[image: ${text || h}]`}
      </a>
    );
  },
  h1: heading("h3", "mt-6 text-lg font-semibold"),
  h2: heading("h3", "mt-6 text-lg font-semibold"),
  h3: heading("h4", "mt-5 font-semibold"),
  h4: heading("h5", "mt-4 font-semibold"),
  h5: heading("h6", "mt-4 font-medium"),
  h6: heading("h6", "mt-4 font-medium"),
  p: ({ children }) => <p className="mt-3 break-words">{children}</p>,
  ul: ({ children }) => <ul className="mt-3 list-disc pl-6">{children}</ul>,
  ol: ({ children }) => <ol className="mt-3 list-decimal pl-6">{children}</ol>,
  blockquote: ({ children }) => (
    <blockquote className="mt-3 border-l-4 border-zinc-300 pl-4 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400">
      {children}
    </blockquote>
  ),
  pre: ({ children }) => (
    <pre className="mt-3 overflow-x-auto rounded bg-zinc-100 p-3 text-sm dark:bg-zinc-900 [&>code]:bg-transparent [&>code]:p-0">
      {children}
    </pre>
  ),
  code: ({ children }) => (
    <code className="rounded bg-zinc-100 px-1 font-mono text-[0.9em] dark:bg-zinc-900">{children}</code>
  ),
  hr: () => <hr className="my-6 border-zinc-300 dark:border-zinc-700" />,
};

const options: Pick<Options, "components" | "urlTransform" | "rehypePlugins"> = {
  components,
  urlTransform: (url) => safeUrl(url),
  rehypePlugins: [flattenLinkedImages],
};

export function Readme({ text }: { text: string }) {
  return <ReactMarkdown {...options}>{capReadme(text)}</ReactMarkdown>;
}
