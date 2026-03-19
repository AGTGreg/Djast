import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { fetchSchema, type SchemaResponse, type ModelSchema, type AppSchema } from '../api/admin';

interface SchemaContextValue {
  apps: Record<string, AppSchema> | null;
  loading: boolean;
  error: string | null;
  getModelConfig: (app: string, model: string) => ModelSchema | null;
  getDefaultRoute: () => string;
  refresh: () => Promise<void>;
}

const SchemaContext = createContext<SchemaContextValue | null>(null);

export function useSchema() {
  const ctx = useContext(SchemaContext);
  if (!ctx) throw new Error('useSchema must be used within SchemaProvider');
  return ctx;
}

export function SchemaProvider({ children }: { children: ReactNode }) {
  const [apps, setApps] = useState<Record<string, AppSchema> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data: SchemaResponse = await fetchSchema();
      setApps(data.apps);
    } catch (err: any) {
      setError(err.message || 'Failed to load schema');
    } finally {
      setLoading(false);
    }
  }, []);

  const getModelConfig = useCallback(
    (app: string, model: string): ModelSchema | null => {
      return apps?.[app]?.models?.[model] ?? null;
    },
    [apps],
  );

  const getDefaultRoute = useCallback((): string => {
    if (!apps) return '/';
    const firstApp = Object.keys(apps)[0];
    if (!firstApp) return '/';
    const firstModel = Object.keys(apps[firstApp].models)[0];
    if (!firstModel) return '/';
    return `/${firstApp}/${firstModel}`;
  }, [apps]);

  return (
    <SchemaContext.Provider value={{ apps, loading, error, getModelConfig, getDefaultRoute, refresh }}>
      {children}
    </SchemaContext.Provider>
  );
}
