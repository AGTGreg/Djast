import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import { SchemaProvider, useSchema } from './context/SchemaContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { ModalProvider } from './context/ModalContext';
import LoginScreen from './components/screens/LoginScreen';
import AdminShell from './components/layout/AdminShell';
import ListScreen from './components/screens/ListScreen';
import DetailScreen from './components/screens/DetailScreen';
import DeleteConfirmModal from './components/shared/DeleteConfirmModal';
import ChangePasswordModal from './components/shared/ChangePasswordModal';
import Spinner from './components/shared/Spinner';

function ListScreenKeyed() {
  const { app, model } = useParams();
  return <ListScreen key={`${app}-${model}`} />;
}

function AppRoutes() {
  const { isLoggedIn, loading: authLoading, logout } = useAuth();
  const { apps, loading: schemaLoading, error: schemaError, getDefaultRoute } = useSchema();

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Spinner />
      </div>
    );
  }

  if (!isLoggedIn) {
    return <LoginScreen />;
  }

  if (schemaLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Spinner />
      </div>
    );
  }

  if (schemaError || !apps) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <p className="text-gray-500 mb-4">{schemaError || 'Unable to load admin configuration.'}</p>
          <button className="btn-secondary" onClick={logout}>
            Sign out
          </button>
        </div>
      </div>
    );
  }

  return (
    <Routes>
      <Route element={<AdminShell />}>
        <Route path="/:app/:model" element={<ListScreenKeyed />} />
        <Route path="/:app/:model/:id" element={<DetailScreen />} />
      </Route>
      <Route path="*" element={<Navigate to={getDefaultRoute()} replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter basename="/admin">
      <SchemaProvider>
        <AuthProvider>
          <ToastProvider>
            <ModalProvider>
              <AppRoutes />
              <DeleteConfirmModal />
              <ChangePasswordModal />
            </ModalProvider>
          </ToastProvider>
        </AuthProvider>
      </SchemaProvider>
    </BrowserRouter>
  );
}
