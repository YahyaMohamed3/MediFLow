import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface DashboardData {
  patients: number;
  appointments: number;
  revenue: number;
}

function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/dashboard').then(res => {
      setData(res.data);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-center mt-20">Loading...</div>;
  }

  if (!data) {
    return <div className="text-center mt-20">No data</div>;
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="grid grid-cols-3 gap-4">
        <div className="p-4 rounded bg-blue-100 text-center">
          <div className="text-sm text-gray-600">Patients</div>
          <div className="text-3xl font-bold">{data.patients}</div>
        </div>
        <div className="p-4 rounded bg-blue-100 text-center">
          <div className="text-sm text-gray-600">Appointments</div>
          <div className="text-3xl font-bold">{data.appointments}</div>
        </div>
        <div className="p-4 rounded bg-blue-100 text-center">
          <div className="text-sm text-gray-600">Total Revenue</div>
          <div className="text-3xl font-bold">${'{'}data.revenue{'}'}</div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
