import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Prescription {
  prescription_id: number;
  patient_id: number;
  medication: string;
  dosage: string;
  instructions: string;
  date_prescribed: string;
}

function Prescriptions() {
  const [items, setItems] = useState<Prescription[]>([]);

  useEffect(() => {
    axios.get('/api/prescriptions').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Prescriptions</h1>
      <table className="w-full bg-gray-800/40 rounded text-sm">
        <thead>
          <tr>
            <th className="p-2 text-left">Patient</th>
            <th className="p-2 text-left">Medication</th>
            <th className="p-2 text-left">Dosage</th>
            <th className="p-2 text-left">Instructions</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(p => (
            <tr key={p.prescription_id} className="border-t border-gray-700">
              <td className="p-2">{p.patient_id}</td>
              <td className="p-2">{p.medication}</td>
              <td className="p-2">{p.dosage}</td>
              <td className="p-2">{p.instructions}</td>
              <td className="p-2">{p.date_prescribed?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Prescriptions;
