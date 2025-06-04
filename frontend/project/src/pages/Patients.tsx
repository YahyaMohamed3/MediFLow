import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Patient {
  patient_id: number;
  name: string;
  date_of_birth: string;
  gender: string;
  phone: string;
  email: string;
  address: string;
  insurance: string;
}

function Patients() {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/patients').then(res => {
      setPatients(res.data);
    }).finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Patients</h1>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <table className="w-full text-left border">
          <thead>
            <tr>
              <th className="border px-2 py-1">Name</th>
              <th className="border px-2 py-1">DOB</th>
              <th className="border px-2 py-1">Gender</th>
              <th className="border px-2 py-1">Phone</th>
              <th className="border px-2 py-1">Email</th>
            </tr>
          </thead>
          <tbody>
            {patients.map(p => (
              <tr key={p.patient_id} className="odd:bg-gray-100">
                <td className="border px-2 py-1">{p.name}</td>
                <td className="border px-2 py-1">{p.date_of_birth}</td>
                <td className="border px-2 py-1">{p.gender}</td>
                <td className="border px-2 py-1">{p.phone}</td>
                <td className="border px-2 py-1">{p.email}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Patients;
