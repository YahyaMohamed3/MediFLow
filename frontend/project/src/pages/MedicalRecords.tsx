import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Record {
  record_id: number;
  patient_name: string;
  description: string;
}

function MedicalRecords() {
  const [records, setRecords] = useState<Record[]>([]);
  useEffect(() => {
    axios.get('/api/medical-records').then(res => setRecords(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Medical Records</h1>
      <ul className="space-y-2">
        {records.map(r => (
          <li key={r.record_id} className="bg-gray-800/40 rounded p-3">
            <div className="font-bold">{r.patient_name}</div>
            <div>{r.description}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default MedicalRecords;
