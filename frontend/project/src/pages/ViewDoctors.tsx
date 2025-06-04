import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Doctor {
  doctor_id: number;
  first_name: string;
  last_name: string;
  specialization: string;
}

function ViewDoctors() {
  const [doctors, setDoctors] = useState<Doctor[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/view_doctors').then(res => {
      setDoctors(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Doctors</h1>
      {loading ? <p>Loading...</p> : (
        <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
          {doctors.map(doc => (
            <div key={doc.doctor_id} className="bg-gray-800/80 p-4 rounded shadow">
              <h2 className="font-semibold">Dr. {doc.last_name}</h2>
              <p className="text-sm">{doc.specialization}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ViewDoctors;
