import { useState, useRef, useEffect } from 'react';
import { Menu, User, ChevronDown, ChevronRight, Key, LogOut } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { useModal } from '../../context/ModalContext';

interface TopBarProps {
  onHamburgerClick: () => void;
  isDetailView?: boolean;
  isNewRecord?: boolean;
  recordId?: number | string;
}

export default function TopBar({ onHamburgerClick, isDetailView, isNewRecord, recordId }: TopBarProps) {
  const { username, logout } = useAuth();
  const { showToast } = useToast();
  const { openChangePasswordModal } = useModal();
  const navigate = useNavigate();
  const { app, model } = useParams();

  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, []);

  const handleLogout = () => {
    setMenuOpen(false);
    showToast('Logged out successfully', 'success');
    setTimeout(() => logout(), 500);
  };

  const handleChangePassword = () => {
    setMenuOpen(false);
    openChangePasswordModal();
  };

  return (
    <header className="sticky top-0 z-10 bg-white/80 backdrop-blur-md border-b border-gray-100 px-4 lg:px-8 py-3 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <button className="lg:hidden btn-ghost p-2" onClick={onHamburgerClick}>
          <Menu className="w-5 h-5" />
        </button>

        {/* Breadcrumb */}
        <nav className="text-sm text-gray-500 flex items-center">
          {app && (
            <>
              <span className="text-gray-400">{app}</span>
              <ChevronRight className="w-3.5 h-3.5 inline mx-1.5 text-gray-300" />
            </>
          )}
          {model && !isDetailView && (
            <span className="font-medium text-brand-charcoal">{model}</span>
          )}
          {model && isDetailView && (
            <>
              <a
                className="hover:text-brand-green cursor-pointer transition-colors"
                onClick={() => navigate(`/${app}/${model}`)}
              >
                {model}
              </a>
              <ChevronRight className="w-3.5 h-3.5 inline mx-1.5 text-gray-300" />
              <span className="font-medium text-brand-charcoal">
                {isNewRecord ? 'Add new' : `#${recordId}`}
              </span>
            </>
          )}
        </nav>
      </div>

      {/* User menu */}
      <div className="relative" ref={menuRef}>
        <button
          className="flex items-center gap-2 btn-ghost px-3 py-1.5"
          onClick={() => setMenuOpen(!menuOpen)}
        >
          <div className="w-8 h-8 rounded-full bg-brand-green/20 flex items-center justify-center">
            <User className="w-4 h-4 text-brand-green" />
          </div>
          <span className="hidden sm:inline text-sm font-medium">{username}</span>
          <ChevronDown className="w-4 h-4" />
        </button>

        {menuOpen && (
          <div className="absolute right-0 mt-2 w-48 card py-1 shadow-lg overflow-hidden">
            <button
              className="w-full text-left px-4 py-2.5 text-sm hover:bg-brand-green/10 transition-colors flex items-center gap-2"
              onClick={handleChangePassword}
            >
              <Key className="w-4 h-4" />
              Change Password
            </button>
            <button
              className="w-full text-left px-4 py-2.5 text-sm hover:bg-brand-green/10 transition-colors flex items-center gap-2 text-brand-red"
              onClick={handleLogout}
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
