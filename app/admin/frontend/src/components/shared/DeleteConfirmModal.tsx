import { AlertTriangle } from 'lucide-react';
import { useModal } from '../../context/ModalContext';

export default function DeleteConfirmModal() {
  const { deleteModal, closeDeleteModal } = useModal();

  if (!deleteModal.open) return null;

  return (
    <div className="modal-overlay visible" onClick={closeDeleteModal}>
      <div className="modal-panel" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-brand-red" />
          </div>
          <h2 className="text-xl font-bold">Confirm Deletion</h2>
        </div>
        <p className="text-gray-600 mb-6">
          Are you sure you want to delete {deleteModal.count}{' '}
          {deleteModal.count === 1 ? 'record' : 'records'}? This action cannot be undone.
        </p>
        <div className="flex justify-end gap-3">
          <button className="btn-secondary" onClick={closeDeleteModal}>
            Cancel
          </button>
          <button
            className="btn-danger"
            onClick={() => {
              deleteModal.onConfirm?.();
              closeDeleteModal();
            }}
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}
