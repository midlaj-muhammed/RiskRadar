"use client";

import { useState, type ReactNode } from "react";

// Client-side paginated table. The server passes the header row and an array of
// already-rendered <tr> rows (latest-first); this shows `pageSize` at a time with
// 1 / 2 / 3 / Next controls and wraps the table in a horizontal-scroll container
// so wide tables never get clipped on mobile.
export function PaginatedTable({
  head,
  rows,
  pageSize = 12,
  empty
}: {
  head: ReactNode;
  rows: ReactNode[];
  pageSize?: number;
  empty?: ReactNode;
}) {
  const [page, setPage] = useState(1);
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, pages);
  const start = (current - 1) * pageSize;
  const shown = rows.slice(start, start + pageSize);

  // Windowed page numbers: always show first/last, and a window around current.
  const numbers: number[] = [];
  for (let p = 1; p <= pages; p++) {
    if (p === 1 || p === pages || (p >= current - 1 && p <= current + 1)) numbers.push(p);
  }

  return (
    <>
      <div className="table-scroll">
        <table>
          <thead>{head}</thead>
          <tbody>{total === 0 ? empty : shown}</tbody>
        </table>
      </div>
      {pages > 1 && (
        <nav className="pager" aria-label="Pagination">
          <button type="button" className="pager-btn" onClick={() => setPage(current - 1)} disabled={current === 1}>‹ Prev</button>
          {numbers.map((p, i) => {
            const gap = i > 0 && p - numbers[i - 1]! > 1;
            return (
              <span key={p} style={{ display: "inline-flex", alignItems: "center" }}>
                {gap && <span className="pager-gap">…</span>}
                <button type="button" className={`pager-btn${p === current ? " active" : ""}`} onClick={() => setPage(p)}>{p}</button>
              </span>
            );
          })}
          <button type="button" className="pager-btn" onClick={() => setPage(current + 1)} disabled={current === pages}>Next ›</button>
          <span className="pager-info">{start + 1}–{Math.min(start + pageSize, total)} of {total} · newest first</span>
        </nav>
      )}
    </>
  );
}
