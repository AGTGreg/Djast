import { useState } from 'react';
import { useModal } from '../../context/ModalContext';
import { useToast } from '../../context/ToastContext';
import { changePassword } from '../../api/admin';
import Spinner from './Spinner';

export default function ChangePasswordModal() {
  const { changePasswordModal, closeChangePasswordModal } = useModal();
  const { showToast } = useToast();

  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  if (!changePasswordModal.open) return null;

  const handleClose = () => {
    setOldPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setError('');
    closeChangePasswordModal();
  };

  const handleSubmit = async () => {
    setError('');
    if (!oldPassword || !newPassword || !confirmPassword) {
      setError('All fields are required.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }

    setSaving(true);
    try {
      await changePassword(oldPassword, newPassword);
      showToast('Password changed successfully');
      handleClose();
    } catch (err: any) {
      setError(err.detail || err.message || 'Failed to change password');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay visible" onClick={handleClose}>
      <div className="modal-panel" onClick={e => e.stopPropagation()}>
        <h2 className="text-xl font-bold mb-4">Change Password</h2>
        <div className="space-y-4">
          <div>
            <label className="form-label">Current Password</label>
            <input
              type="password"
              className="form-field"
              placeholder="Enter current password"
              value={oldPassword}
              onChange={e => { setOldPassword(e.target.value); setError(''); }}
            />
          </div>
          <div>
            <label className="form-label">New Password</label>
            <input
              type="password"
              className="form-field"
              placeholder="Enter new password"
              value={newPassword}
              onChange={e => { setNewPassword(e.target.value); setError(''); }}
            />
          </div>
          <div>
            <label className="form-label">Confirm New Password</label>
            <input
              type="password"
              className="form-field"
              placeholder="Enter new password again"
              value={confirmPassword}
              onChange={e => { setConfirmPassword(e.target.value); setError(''); }}
            />
          </div>
        </div>
        {error && (
          <div className="text-sm text-brand-red mt-3">{error}</div>
        )}
        <div className="flex justify-end gap-3 mt-6">
          <button className="btn-secondary" onClick={handleClose}>
            Cancel
          </button>
          <button className="btn-primary" onClick={handleSubmit} disabled={saving}>
            {saving ? <Spinner /> : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
