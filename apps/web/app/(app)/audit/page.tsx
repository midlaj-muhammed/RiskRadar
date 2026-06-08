import { JsonDatabase } from "@riskradar/core";
import { PaginatedTable } from "../../../components/PaginatedTable";

export default function AuditPage() {
  const receipts = new JsonDatabase().read().auditReceipts.slice().reverse();
  const rows = receipts.map((receipt) => {
    const target = `${receipt.targetType}:${receipt.targetId}`;
    const prev = receipt.previousReceiptHash ?? "";
    return (
      <tr key={receipt.id}>
        <td data-label="Receipt"><span className="id" title={receipt.id}>{receipt.id}</span></td>
        <td data-label="Action">{receipt.action}</td>
        <td data-label="Actor">{receipt.actorType}</td>
        <td data-label="Target"><span className="list-trunc" title={target}>{target}</span></td>
        <td data-label="Hash"><span className="id-sm" title={receipt.receiptHash}>{receipt.receiptHash.slice(0, 10)}</span></td>
        <td data-label="Previous">{prev ? <span className="id-sm" title={prev}>{prev.slice(0, 10)}</span> : <span className="muted">genesis</span>}</td>
      </tr>
    );
  });
  return (
    <>
      <div className="topline">Tamper-evident receipt hash chain</div>
      <h1>Audit Receipts</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <PaginatedTable
          head={<tr><th>Receipt</th><th>Action</th><th>Actor</th><th>Target</th><th>Hash</th><th>Previous</th></tr>}
          rows={rows}
          pageSize={12}
          empty={<tr><td colSpan={6} className="muted">No audit receipts yet.</td></tr>}
        />
      </section>
    </>
  );
}
