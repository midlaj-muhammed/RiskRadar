"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

/** A copy-pasteable command with a real one-click copy button. */
export function CopyCommand({ command, label }: { command: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard blocked — the text is still selectable */
    }
  }
  return (
    <div className="lp-install">
      {label ? <span className="lp-install-label">{label}</span> : null}
      <div className="lp-install-box">
        <code className="lp-install-cmd"><span className="lp-install-prompt">$</span>{command}</code>
        <button type="button" className="lp-copy" onClick={copy} aria-label="Copy command">
          {copied ? <Check size={15} /> : <Copy size={15} />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
    </div>
  );
}
