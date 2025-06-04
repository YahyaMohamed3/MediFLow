import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

interface Patient {
  patient_id: number;
  patient_name: string;
  height_medical?: string;
  weight_medical?: string;
  blood_type_medical?: string;
}

function DoctorRecords() {
  const [patients, setPatients] = useState<Patient[]>([]);

  useEffect(() => {
    axios.get('/api/doctor/patients').then(res => setPatients(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-xl font-bold mb-4">Patients</h1>
      <ul className="space-y-2">
        {patients.map(p => (
          <li key={p.patient_id} className="border-b border-gray-700 pb-2">
            <Link to={`/records/${p.patient_id}`} className="text-blue-400 hover:underline">
              {p.patient_name}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default DoctorRecords;
