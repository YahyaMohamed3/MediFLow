import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Appt {
  appointmentdate: string;
  starttime: string;
  reason: string;
  notes: string;
  patient_name: string;
}

function DoctorDashboard() {
  const [appointments, setAppointments] = useState<Appt[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/doctor/dashboard').then(res => {
      setAppointments(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Today’s Appointments</h1>
      {loading ? <p>Loading...</p> : (
        <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
          {appointments.map((a, i) => (
            <div key={i} className="bg-gray-800/80 p-4 rounded shadow">
              <h2 className="font-semibold">{a.patient_name}</h2>
              <p className="text-sm">{a.reason}</p>
              <p className="text-sm">{a.appointmentdate} {a.starttime}</p>
              {a.notes && <p className="text-xs mt-2 opacity-80">{a.notes}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default DoctorDashboard;
