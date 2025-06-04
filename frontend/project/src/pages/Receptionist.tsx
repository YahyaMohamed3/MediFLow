import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Appt {
  start_time: string;
  name: string;
  date_of_birth: string;
}

function Receptionist() {
  const [appointments, setAppointments] = useState<Appt[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/receptionist').then(res => {
      setAppointments(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Today’s Appointments</h1>
      {loading ? <p>Loading...</p> : (
        <table className="w-full bg-gray-800/80 rounded">
          <thead>
            <tr>
              <th className="p-2 text-left">Time</th>
              <th className="p-2 text-left">Patient</th>
              <th className="p-2 text-left">DOB</th>
            </tr>
          </thead>
          <tbody>
            {appointments.map((a, i) => (
              <tr key={i} className="border-t border-gray-700">
                <td className="p-2">{a.start_time}</td>
                <td className="p-2">{a.name}</td>
                <td className="p-2">{a.date_of_birth}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Receptionist;
