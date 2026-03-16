import { useState, useRef, useEffect } from 'react';
import { useParams, useNavigate, useOutletContext } from 'react-router-dom';
import { ArrowLeft, Trash2, Check, Key } from 'lucide-react';
import {
  fetchRecord,
  createRecord,
  updateRecord,
  deleteRecord,
  adminSetPassword,
} from '../../api/admin';
import { useSchema } from '../../context/SchemaContext';
import type { FieldConfig, RecordData } from '../../data/types';
import { useToast } from '../../context/ToastContext';
import { useModal } from '../../context/ModalContext';
import TopBar from '../layout/TopBar';
import Spinner from '../shared/Spinner';

export default function DetailScreen() {
  const { app = '', model = '', id } = useParams();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const { openDeleteModal } = useModal();
  const { getModelConfig } = useSchema();
  const { onHamburgerClick } = useOutletContext<{ onHamburgerClick: () => void }>();
  const formRef = useRef<HTMLDivElement>(null);

  const isNew = id === 'new';
  const config = getModelConfig(app, model);
  const fields = config?.fields ?? [];
  const hasPasswordChange = config?.has_password_change ?? false;

  const [record, setRecord] = useState<RecordData | null>(null);
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  // Password change state
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSaving, setPasswordSaving] = useState(false);

  // Load record
  useEffect(() => {
    if (isNew) return;
    (async () => {
      try {
        const data = await fetchRecord(app, model, id!);
        setRecord(data);
      } catch {
        setRecord(null);
      } finally {
        setLoading(false);
      }
    })();
  }, [app, model, id, isNew]);

  if (loading) {
    return (
      <>
        <TopBar onHamburgerClick={onHamburgerClick} isDetailView isNewRecord={false} recordId={id} />
        <main className="flex-1 p-4 lg:p-8 flex items-center justify-center">
          <Spinner />
        </main>
      </>
    );
  }

  if (!isNew && !record) {
    return (
      <>
        <TopBar onHamburgerClick={onHamburgerClick} isDetailView isNewRecord={false} recordId={id} />
        <main className="flex-1 p-4 lg:p-8">
          <p className="text-gray-500">Record not found.</p>
        </main>
      </>
    );
  }

  const getFormValues = (): RecordData => {
    const values: RecordData = {};
    if (!formRef.current) return values;

    fields.forEach(field => {
      if (field.name === 'id' || !field.editable) return;
      const input = formRef.current!.querySelector(`[data-field="${field.name}"]`) as HTMLInputElement | HTMLSelectElement | null;
      if (!input) return;
      if (field.type === 'boolean') {
        values[field.name] = (input as HTMLInputElement).checked;
      } else if (field.type === 'integer' && field.editable) {
        values[field.name] = parseInt(input.value, 10) || 0;
      } else if (field.type === 'decimal' && field.editable) {
        values[field.name] = parseFloat(input.value) || 0;
      } else {
        values[field.name] = input.value;
      }
    });

    return values;
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    const values = getFormValues();

    try {
      if (isNew) {
        // For user models creating via admin, include password from a
        // dedicated field if present
        const pwInput = formRef.current?.querySelector('[data-field="__password"]') as HTMLInputElement | null;
        if (hasPasswordChange && pwInput?.value) {
          values.password = pwInput.value;
        }
        await createRecord(app, model, values);
        showToast(`${model} created successfully`, 'success');
      } else {
        await updateRecord(app, model, id!, values);
        showToast(`${model} #${record?.id} saved`, 'success');
      }
      navigate(`/${app}/${model}`);
    } catch (err: any) {
      setError(err.detail || err.message || 'Save failed');
      showToast(err.detail || 'Save failed', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = () => {
    if (!record) return;
    openDeleteModal(1, async () => {
      try {
        await deleteRecord(app, model, record.id as number);
        showToast(`${model} #${record.id} deleted`, 'success');
        navigate(`/${app}/${model}`);
      } catch (err: any) {
        showToast(err.message || 'Delete failed', 'error');
      }
    });
  };

  const handlePasswordChange = async () => {
    setPasswordError('');
    if (!newPassword) {
      setPasswordError('Password is required.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match.');
      return;
    }
    setPasswordSaving(true);
    try {
      await adminSetPassword(app, model, id!, newPassword);
      showToast('Password changed successfully', 'success');
      setShowPasswordForm(false);
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setPasswordError(err.detail || err.message || 'Failed to change password');
    } finally {
      setPasswordSaving(false);
    }
  };

  return (
    <>
      <TopBar
        onHamburgerClick={onHamburgerClick}
        isDetailView
        isNewRecord={isNew}
        recordId={record?.id as number}
      />
      <main className="flex-1 p-4 lg:p-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <button className="btn-ghost p-2" onClick={() => navigate(`/${app}/${model}`)}>
              <ArrowLeft className="w-5 h-5" />
            </button>
            <h2 className="text-2xl font-bold">
              {isNew ? `Add ${model}` : `${model} #${record?.id}`}
            </h2>
          </div>
          <div className="flex items-center gap-3">
            {!isNew && (
              <button className="btn-danger" onClick={handleDelete}>
                <Trash2 className="w-4 h-4" />
                <span>Delete</span>
              </button>
            )}
            <button className="btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? <Spinner /> : (
                <>
                  <Check className="w-4 h-4" />
                  <span>Save</span>
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="text-sm text-brand-red bg-red-50 border border-red-100 rounded-input px-4 py-2.5 mb-4">
            {error}
          </div>
        )}

        {/* Form card */}
        <div className="card p-6 lg:p-8">
          <div ref={formRef} className="space-y-5 max-w-2xl">
            {fields.map(field => {
              if (isNew && !field.editable) return null;
              return (
                <FormRow
                  key={field.name}
                  field={field}
                  value={record ? record[field.name] : ''}
                  isNew={isNew}
                />
              );
            })}

            {/* Password field for new user records */}
            {isNew && hasPasswordChange && (
              <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-6 py-3 border-b border-gray-100">
                <label className="text-sm font-semibold text-brand-charcoal sm:w-48 sm:shrink-0 capitalize">
                  password
                </label>
                <div className="flex-1">
                  <input
                    type="password"
                    className="form-field"
                    data-field="__password"
                    placeholder="Enter password"
                  />
                </div>
              </div>
            )}

            {/* Password change button for existing user records */}
            {!isNew && hasPasswordChange && (
              <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-6 py-3 border-b border-gray-100">
                <label className="text-sm font-semibold text-brand-charcoal sm:w-48 sm:shrink-0 capitalize">
                  password
                </label>
                <div className="flex-1">
                  {!showPasswordForm ? (
                    <button
                      className="btn-secondary text-sm"
                      onClick={() => setShowPasswordForm(true)}
                    >
                      <Key className="w-4 h-4" />
                      <span>Change password</span>
                    </button>
                  ) : (
                    <div className="space-y-3">
                      <input
                        type="password"
                        className="form-field"
                        placeholder="New password"
                        value={newPassword}
                        onChange={e => { setNewPassword(e.target.value); setPasswordError(''); }}
                      />
                      <input
                        type="password"
                        className="form-field"
                        placeholder="Confirm new password"
                        value={confirmPassword}
                        onChange={e => { setConfirmPassword(e.target.value); setPasswordError(''); }}
                      />
                      {passwordError && (
                        <div className="text-sm text-brand-red">{passwordError}</div>
                      )}
                      <div className="flex gap-2">
                        <button
                          className="btn-primary text-sm"
                          onClick={handlePasswordChange}
                          disabled={passwordSaving}
                        >
                          {passwordSaving ? <Spinner /> : 'Save password'}
                        </button>
                        <button
                          className="btn-secondary text-sm"
                          onClick={() => {
                            setShowPasswordForm(false);
                            setNewPassword('');
                            setConfirmPassword('');
                            setPasswordError('');
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}

// ─── Form row ────────────────────────────────────────────────
function FormRow({ field, value, isNew }: { field: FieldConfig; value: unknown; isNew: boolean }) {
  const label = field.name.replace(/_/g, ' ');

  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-6 py-3 border-b border-gray-100">
      <label className="text-sm font-semibold text-brand-charcoal sm:w-48 sm:shrink-0 capitalize">
        {label}
      </label>
      <div className="flex-1">
        <FieldInput field={field} value={value} isNew={isNew} />
      </div>
    </div>
  );
}

// ─── Field input renderer ────────────────────────────────────
function FieldInput({ field, value, isNew }: { field: FieldConfig; value: unknown; isNew: boolean }) {
  if (field.type === 'select') {
    return (
      <select
        className={field.editable ? 'form-field' : 'form-field form-field-readonly'}
        data-field={field.name}
        disabled={!field.editable}
        defaultValue={String(value ?? '')}
      >
        {(field.options ?? []).map(opt => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
    );
  }

  if (field.type === 'boolean') {
    return <BooleanField field={field} initialValue={!!value} />;
  }

  const inputType = field.type === 'email' ? 'email'
    : (field.type === 'integer' || field.type === 'decimal') ? 'number'
    : 'text';

  return (
    <input
      type={inputType}
      className={field.editable ? 'form-field' : 'form-field form-field-readonly'}
      data-field={field.name}
      defaultValue={value != null ? String(value) : ''}
      placeholder={isNew ? `Enter ${field.name.replace(/_/g, ' ')}` : ''}
      readOnly={!field.editable}
    />
  );
}

// ─── Boolean field with label toggle ─────────────────────────
function BooleanField({ field, initialValue }: { field: FieldConfig; initialValue: boolean }) {
  const [checked, setChecked] = useState(initialValue);

  return (
    <div className="flex items-center gap-3 py-1">
      <input
        type="checkbox"
        className={field.editable
          ? 'w-5 h-5 rounded cursor-pointer accent-brand-green'
          : 'w-5 h-5 rounded cursor-not-allowed opacity-60'
        }
        data-field={field.name}
        checked={checked}
        disabled={!field.editable}
        onChange={e => setChecked(e.target.checked)}
      />
      <span className={`text-sm ${checked ? 'text-brand-green' : 'text-gray-400'}`}>
        {checked ? 'Yes' : 'No'}
      </span>
    </div>
  );
}
