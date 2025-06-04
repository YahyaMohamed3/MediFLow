import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Doctor {
  doctor_id: number;
  email: string;
  first_name: string;
  last_name: string;
  specialization: string;
  phone: string;
}

function Doctors() {
  const [doctors, setDoctors] = useState<Doctor[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/doctors').then(res => {
      setDoctors(res.data);
    }).finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Doctors</h1>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <table className="w-full text-left border">
          <thead>
            <tr>
              <th className="border px-2 py-1">Email</th>
              <th className="border px-2 py-1">Name</th>
              <th className="border px-2 py-1">Specialization</th>
              <th className="border px-2 py-1">Phone</th>
            </tr>
          </thead>
          <tbody>
            {doctors.map(d => (
              <tr key={d.doctor_id} className="odd:bg-gray-100">
                <td className="border px-2 py-1">{d.email}</td>
                <td className="border px-2 py-1">{d.first_name} {d.last_name}</td>
                <td className="border px-2 py-1">{d.specialization}</td>
                <td className="border px-2 py-1">{d.phone}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Doctors;
