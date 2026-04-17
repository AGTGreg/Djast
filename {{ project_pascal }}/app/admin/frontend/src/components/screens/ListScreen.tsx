import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, useOutletContext } from 'react-router-dom';
import { Plus, Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Trash2, Inbox } from 'lucide-react';
import { fetchRecords, bulkDeleteRecords } from '../../api/admin';
import { formatFieldValue, STATUS_COLORS } from '../../data/formatters';
import { useSchema } from '../../context/SchemaContext';
import type { RecordData } from '../../data/types';
import { useToast } from '../../context/ToastContext';
import { useModal } from '../../context/ModalContext';
import TopBar from '../layout/TopBar';
import Spinner from '../shared/Spinner';

const PAGE_SIZE = 100;

export default function ListScreen() {
  const { app = '', model = '' } = useParams();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const { openDeleteModal } = useModal();
  const { getModelConfig } = useSchema();
  const { onHamburgerClick } = useOutletContext<{ onHamburgerClick: () => void }>();

  const [searchQuery, setSearchQuery] = useState('');
  const [ordering, setOrdering] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedRows, setSelectedRows] = useState<Set<string | number>>(new Set());
  const [bulkDropdownOpen, setBulkDropdownOpen] = useState(false);
  const bulkDropdownRef = useRef<HTMLDivElement>(null);

  const [data, setData] = useState<RecordData[]>([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);

  const config = getModelConfig(app, model);
  const allFields = config?.fields ?? [];
  const pkField = config?.pk_field ?? 'id';
  const listDisplay = config?.list_display;
  const searchFields = config?.search_fields;
  const hasSearch = searchFields != null && searchFields.length > 0;
  const fields = listDisplay
    ? allFields.filter(f => listDisplay.includes(f.name))
    : allFields;

  // Reset state when navigating between models
  useEffect(() => {
    setSearchQuery('');
    setDebouncedSearch('');
    setOrdering(null);
    setCurrentPage(1);
    setSelectedRows(new Set());
  }, [app, model]);

  // Debounced search
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [debouncedSearch, setDebouncedSearch] = useState('');

  useEffect(() => {
    searchTimerRef.current = setTimeout(() => {
      setDebouncedSearch(searchQuery);
      setCurrentPage(1);
    }, 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [searchQuery]);

  // Close bulk dropdown on outside click
  useEffect(() => {
    if (!bulkDropdownOpen) return;
    const handler = (e: MouseEvent) => {
      if (bulkDropdownRef.current && !bulkDropdownRef.current.contains(e.target as Node)) {
        setBulkDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [bulkDropdownOpen]);

  // Fetch data from server
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await fetchRecords(app, model, {
        page: currentPage,
        page_size: PAGE_SIZE,
        search: debouncedSearch || undefined,
        ordering: ordering || undefined,
      });
      setData(result.results);
      setTotalRecords(result.count);
      setTotalPages(result.total_pages);
    } catch (err: any) {
      showToast(err.message || 'Failed to load records', 'error');
    } finally {
      setLoading(false);
    }
  }, [app, model, currentPage, debouncedSearch, ordering]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSort = useCallback((fieldName: string) => {
    setOrdering(prev => {
      if (prev === fieldName) return `-${fieldName}`;
      if (prev === `-${fieldName}`) return null;
      return fieldName;
    });
  }, []);

  const toggleRow = useCallback((pk: string | number) => {
    setSelectedRows(prev => {
      const next = new Set(prev);
      if (next.has(pk)) next.delete(pk);
      else next.add(pk);
      return next;
    });
  }, []);

  const toggleAllPage = useCallback((checked: boolean) => {
    setSelectedRows(prev => {
      const next = new Set(prev);
      data.forEach(row => {
        const id = row[pkField] as string | number;
        if (checked) next.add(id);
        else next.delete(id);
      });
      return next;
    });
  }, [data]);

  const handleBulkDelete = () => {
    setBulkDropdownOpen(false);
    const ids = Array.from(selectedRows);
    openDeleteModal(ids.length, async () => {
      try {
        await bulkDeleteRecords(app, model, ids);
        setSelectedRows(new Set());
        showToast(`${ids.length} record${ids.length > 1 ? 's' : ''} deleted`, 'success');
        loadData();
      } catch (err: any) {
        showToast(err.message || 'Delete failed', 'error');
      }
    });
  };

  const handleRowClick = (row: RecordData) => {
    navigate(`/${app}/${model}/${row[pkField]}`);
  };

  const allPageSelected = data.length > 0 && data.every(r => selectedRows.has(r[pkField] as string | number));

  const sortField = ordering?.replace(/^-/, '') ?? null;
  const sortDir = ordering?.startsWith('-') ? 'desc' : 'asc';

  return (
    <>
      <TopBar onHamburgerClick={onHamburgerClick} />
      <main className="flex-1 p-4 lg:p-8">
        {/* Toolbar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <h2 className="text-2xl font-bold">{model} List</h2>
          <div className="flex items-center gap-3">
            {selectedRows.size > 0 && (
              <div className="relative" ref={bulkDropdownRef}>
                <button
                  className="btn-secondary text-sm"
                  onClick={() => setBulkDropdownOpen(!bulkDropdownOpen)}
                >
                  <ChevronDown className="w-4 h-4" />
                  <span>Actions</span>
                  <span className="badge badge-green ml-1">{selectedRows.size}</span>
                </button>
                {bulkDropdownOpen && (
                  <div className="absolute right-0 mt-2 w-48 card py-1 shadow-lg z-10 overflow-hidden">
                    <button
                      className="w-full text-left px-4 py-2.5 text-sm hover:bg-brand-green/10 transition-colors flex items-center gap-2 text-brand-red"
                      onClick={handleBulkDelete}
                    >
                      <Trash2 className="w-4 h-4" /> Delete selected
                    </button>
                  </div>
                )}
              </div>
            )}
            <button
              className="btn-primary"
              onClick={() => navigate(`/${app}/${model}/new`)}
            >
              <Plus className="w-4 h-4" />
              <span>Add New</span>
            </button>
          </div>
        </div>

        {/* Search — only shown when model has search_fields configured */}
        {hasSearch && (
          <div className="mb-4">
            <div className="relative">
              <span className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-400">
                <Search className="w-4 h-4" />
              </span>
              <input
                type="text"
                className="form-field form-field-icon"
                placeholder="Search records..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
            </div>
          </div>
        )}

        {/* Table card */}
        <div className="card overflow-hidden">
          {loading ? (
            <div className="py-16 text-center">
              <Spinner />
            </div>
          ) : (
            <div className="overflow-x-auto">
              {data.length > 0 && (
                <table className="w-full">
                  <thead className="bg-brand-gray/50 border-b border-gray-100">
                    <tr>
                      <th className="table-header w-10">
                        <input
                          type="checkbox"
                          className="w-4 h-4 rounded cursor-pointer accent-brand-green"
                          checked={allPageSelected}
                          onChange={e => toggleAllPage(e.target.checked)}
                        />
                      </th>
                      {fields.map(field => (
                        <th
                          key={field.name}
                          className="table-header"
                          onClick={() => handleSort(field.name)}
                        >
                          {field.name.replace(/_/g, ' ')}
                          {sortField === field.name && (
                            sortDir === 'asc'
                              ? <ChevronUp className="w-3.5 h-3.5 inline ml-1 text-brand-green" />
                              : <ChevronDown className="w-3.5 h-3.5 inline ml-1 text-brand-green" />
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.map(row => (
                      <tr
                        key={row[pkField] as string | number}
                        className="table-row cursor-pointer"
                        onClick={() => handleRowClick(row)}
                      >
                        <td className="table-cell w-10">
                          <input
                            type="checkbox"
                            className="w-4 h-4 rounded cursor-pointer accent-brand-green"
                            checked={selectedRows.has(row[pkField] as string | number)}
                            onClick={e => e.stopPropagation()}
                            onChange={() => toggleRow(row[pkField] as string | number)}
                          />
                        </td>
                        {fields.map((field, fi) => (
                          <td
                            key={field.name}
                            className={`table-cell ${fi === 0 || (fi === 1 && !fields[0].editable) ? 'font-medium' : ''}`}
                          >
                            <CellValue value={row[field.name]} field={field} />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {!loading && data.length === 0 && (
            <div className="py-16 text-center">
              <Inbox className="w-12 h-12 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-400 font-medium">No records found</p>
              <p className="text-gray-300 text-sm mt-1">Try adjusting your search or add a new record.</p>
            </div>
          )}
        </div>

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalRecords={totalRecords}
          pageSize={PAGE_SIZE}
          onPageChange={setCurrentPage}
        />
      </main>
    </>
  );
}

// ─── Cell value renderer ─────────────────────────────────────
function CellValue({ value, field }: { value: unknown; field: { name: string; type: string } }) {
  if (field.type === 'boolean') {
    return (
      <span className={`badge ${value ? 'badge-green' : 'badge-gray'}`}>
        {value ? 'Yes' : 'No'}
      </span>
    );
  }

  if (field.type === 'select') {
    const colorClass = STATUS_COLORS[String(value)] || 'badge-gray';
    return <span className={`badge ${colorClass}`}>{String(value ?? '\u2014')}</span>;
  }

  return <>{formatFieldValue(value, field.type)}</>;
}

// ─── Pagination ──────────────────────────────────────────────
function getPaginationRange(current: number, total: number): (number | '...')[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: (number | '...')[] = [1];
  if (current > 3) pages.push('...');
  for (let i = Math.max(2, current - 1); i <= Math.min(total - 1, current + 1); i++) {
    pages.push(i);
  }
  if (current < total - 2) pages.push('...');
  pages.push(total);
  return pages;
}

function Pagination({
  currentPage,
  totalPages,
  totalRecords,
  pageSize,
  onPageChange,
}: {
  currentPage: number;
  totalPages: number;
  totalRecords: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}) {
  const start = (currentPage - 1) * pageSize + 1;
  const end = Math.min(currentPage * pageSize, totalRecords);
  const pages = getPaginationRange(currentPage, totalPages);

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mt-4 text-sm text-gray-500">
      <span>
        {totalRecords === 0 ? '0 records' : `Showing ${start}\u2013${end} of ${totalRecords} records`}
      </span>
      <div className="flex items-center gap-1">
        <button
          className={`btn-ghost px-2.5 py-1.5 text-sm ${currentPage <= 1 ? 'opacity-40 pointer-events-none' : ''}`}
          onClick={() => onPageChange(currentPage - 1)}
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        {pages.map((p, i) =>
          p === '...' ? (
            <span key={`ellipsis-${i}`} className="px-2 py-1.5 text-gray-400">...</span>
          ) : (
            <button
              key={p}
              className={`btn-ghost px-3 py-1.5 text-sm ${p === currentPage ? 'bg-brand-green text-white hover:bg-brand-green' : ''}`}
              onClick={() => onPageChange(p)}
            >
              {p}
            </button>
          )
        )}
        <button
          className={`btn-ghost px-2.5 py-1.5 text-sm ${currentPage >= totalPages ? 'opacity-40 pointer-events-none' : ''}`}
          onClick={() => onPageChange(currentPage + 1)}
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
