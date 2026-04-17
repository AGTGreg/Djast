import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import { setAccessToken } from '../api/client';
import {
  login as apiLogin,
  logout as apiLogout,
  fetchCurrentUser,
  fetchAdminConfig,
} from '../api/admin';
import { useSchema } from './SchemaContext';

interface AuthContextValue {
  isLoggedIn: boolean;
  username: string;
  authType: 'django' | 'email';
  loading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');
  const [authType, setAuthType] = useState<'django' | 'email'>('django');
  const [loading, setLoading] = useState(true);
  const { refresh: refreshSchema } = useSchema();

  // Fetch auth config on mount
  useEffect(() => {
    fetchAdminConfig()
      .then(config => setAuthType(config.auth_type))
      .catch(() => {});
  }, []);

  // Try to restore session from refresh cookie on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const user = await fetchCurrentUser();
        if (cancelled) return;
        setUsername(user.username || user.email);
        setIsLoggedIn(true);
        await refreshSchema();
      } catch {
        // No valid session
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const login = useCallback(async (identifier: string, password: string) => {
    const formData: Record<string, string> = authType === 'django'
      ? { username: identifier, password }
      : { email: identifier, password };

    await apiLogin(formData);
    const user = await fetchCurrentUser();
    setUsername(user.username || user.email);
    setIsLoggedIn(true);
    await refreshSchema();
  }, [authType, refreshSchema]);

  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      // Clear even if API fails
    }
    setAccessToken(null);
    setIsLoggedIn(false);
    setUsername('');
  }, []);

  return (
    <AuthContext.Provider value={{ isLoggedIn, username, authType, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
