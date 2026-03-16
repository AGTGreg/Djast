import { Database } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import { useSchema } from '../../context/SchemaContext';

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export default function Sidebar({ open, onClose }: SidebarProps) {
  const navigate = useNavigate();
  const { app: currentApp, model: currentModel } = useParams();
  const { apps } = useSchema();

  const handleModelClick = (appName: string, modelName: string) => {
    navigate(`/${appName}/${modelName}`);
    if (window.innerWidth < 1024) {
      onClose();
    }
  };

  return (
    <>
      <aside
        className={`fixed inset-y-0 left-0 z-30 w-64 bg-brand-charcoal transform transition-transform duration-300 flex flex-col ${
          open ? 'translate-x-0' : '-translate-x-full'
        } lg:translate-x-0`}
      >
        <div className="px-6 py-5 border-b border-white/10">
          <h1 className="text-xl font-bold text-white tracking-tight">
            Djast <span className="text-brand-green">Admin</span>
          </h1>
        </div>
        <nav className="flex-1 overflow-y-auto py-4 space-y-4">
          {apps && Object.entries(apps).map(([appName, app]) => (
            <div key={appName}>
              <div className="sidebar-app-header">{app.label}</div>
              {Object.keys(app.models).map(modelName => {
                const isActive =
                  currentApp === appName && currentModel === modelName;
                return (
                  <a
                    key={modelName}
                    className={`sidebar-link ${isActive ? 'active' : ''}`}
                    onClick={() => handleModelClick(appName, modelName)}
                  >
                    <Database className="w-4 h-4" />
                    {modelName}
                  </a>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>

      {open && (
        <div
          className="fixed inset-0 z-20 bg-black/40 lg:hidden"
          onClick={onClose}
        />
      )}
    </>
  );
}
