import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

interface DeleteModalState {
  open: boolean;
  count: number;
  onConfirm: (() => void) | null;
}

interface ChangePasswordModalState {
  open: boolean;
}

interface ModalContextValue {
  deleteModal: DeleteModalState;
  openDeleteModal: (count: number, onConfirm: () => void) => void;
  closeDeleteModal: () => void;
  changePasswordModal: ChangePasswordModalState;
  openChangePasswordModal: () => void;
  closeChangePasswordModal: () => void;
}

const ModalContext = createContext<ModalContextValue | null>(null);

export function useModal() {
  const ctx = useContext(ModalContext);
  if (!ctx) throw new Error('useModal must be used within ModalProvider');
  return ctx;
}

export function ModalProvider({ children }: { children: ReactNode }) {
  const [deleteModal, setDeleteModal] = useState<DeleteModalState>({
    open: false,
    count: 0,
    onConfirm: null,
  });
  const [changePasswordModal, setChangePasswordModal] = useState<ChangePasswordModalState>({
    open: false,
  });

  const openDeleteModal = useCallback((count: number, onConfirm: () => void) => {
    setDeleteModal({ open: true, count, onConfirm });
  }, []);

  const closeDeleteModal = useCallback(() => {
    setDeleteModal({ open: false, count: 0, onConfirm: null });
  }, []);

  const openChangePasswordModal = useCallback(() => {
    setChangePasswordModal({ open: true });
  }, []);

  const closeChangePasswordModal = useCallback(() => {
    setChangePasswordModal({ open: false });
  }, []);

  return (
    <ModalContext.Provider
      value={{
        deleteModal,
        openDeleteModal,
        closeDeleteModal,
        changePasswordModal,
        openChangePasswordModal,
        closeChangePasswordModal,
      }}
    >
      {children}
    </ModalContext.Provider>
  );
}
