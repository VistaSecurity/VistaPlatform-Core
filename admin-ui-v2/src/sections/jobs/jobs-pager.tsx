// "Showing N of M" plus prev/next, shared by Jobs & Queues and Job Repair.
import { ChevronLeft, ChevronRight } from 'lucide-react';

export function JobsPager({ page, pageSize, total, shown, onPage }: {
  page: number; pageSize: number; total: number; shown: number; onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span>Showing {shown.toLocaleString()} of {total.toLocaleString()} jobs</span>
      <span>· Page {page} / {pages}</span>
      <button className="op-btn icon sm" aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)}><ChevronLeft size={14} /></button>
      <button className="op-btn icon sm" aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)}><ChevronRight size={14} /></button>
    </span>
  );
}
