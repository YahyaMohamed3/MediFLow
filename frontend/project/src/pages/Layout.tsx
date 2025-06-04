import React from 'react';
import { Outlet, Link } from 'react-router-dom';

function Layout() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white">
      <nav className="p-4 flex gap-4 border-b border-gray-700">
        <Link to="/dashboard">Dashboard</Link>
        <Link to="/patients">Patients</Link>
        <Link to="/appointments">Appointments</Link>
        <Link to="/doctors">Doctors</Link>
        <Link to="/users">Users</Link>
      </nav>
      <div className="p-4">
        <Outlet />
      </div>
    </div>
  );
}

export default Layout;
