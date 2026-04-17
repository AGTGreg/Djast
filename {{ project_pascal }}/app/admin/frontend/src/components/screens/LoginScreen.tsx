import { useState, type FormEvent } from 'react';
import { Mail, Lock, Eye, EyeOff, AlertCircle, User } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import Spinner from '../shared/Spinner';

export default function LoginScreen() {
  const { login, authType } = useAuth();
  const { showToast } = useToast();

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isDjango = authType === 'django';
  const identifierLabel = isDjango ? 'Username' : 'Email';
  const identifierPlaceholder = isDjango ? 'admin' : 'admin@djast.dev';
  const IdentifierIcon = isDjango ? User : Mail;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!identifier.trim() || !password) {
      setError('Please fill in all fields.');
      return;
    }

    setLoading(true);
    try {
      await login(identifier, password);
      showToast('Welcome back!', 'success');
    } catch (err: any) {
      if (err.status === 429) {
        setError('Too many attempts. Please try again later.');
      } else {
        setError(`Invalid ${identifierLabel.toLowerCase()} or password.`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-gradient-to-br from-brand-gray via-white to-brand-gray">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-card bg-brand-charcoal mb-4 shadow-md">
            <svg className="w-8 h-8 text-brand-green" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L2 7l10 5 10-5-10-5z" />
              <path d="M2 17l10 5 10-5" />
              <path d="M2 12l10 5 10-5" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-brand-charcoal">
            Djast <span className="text-brand-green">Admin</span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">Sign in to your account</p>
        </div>

        {/* Login Card */}
        <div className="card p-8">
          <form className="space-y-5" autoComplete="off" onSubmit={handleSubmit}>
            {/* Identifier (username or email) */}
            <div>
              <label className="form-label">{identifierLabel}</label>
              <div className="relative">
                <span className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-400">
                  <IdentifierIcon className="w-4 h-4" />
                </span>
                <input
                  type={isDjango ? 'text' : 'email'}
                  className="form-field form-field-icon"
                  placeholder={identifierPlaceholder}
                  value={identifier}
                  onChange={e => { setIdentifier(e.target.value); setError(''); }}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="form-label">Password</label>
              <div className="relative">
                <span className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-400">
                  <Lock className="w-4 h-4" />
                </span>
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="form-field form-field-icon"
                  placeholder="Enter your password"
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(''); }}
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-brand-charcoal transition-colors"
                  tabIndex={-1}
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="text-sm text-brand-red bg-red-50 border border-red-100 rounded-input px-4 py-2.5 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button type="submit" className="btn-primary w-full py-3" disabled={loading}>
              {loading ? <Spinner /> : <span>Sign In</span>}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
