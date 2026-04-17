import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';

export default function AdminShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div>
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="lg:ml-64 min-h-screen flex flex-col transition-all duration-300">
        <Outlet context={{ onHamburgerClick: () => setSidebarOpen(prev => !prev) }} />
      </div>
    </div>
  );
}
