import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Supply {
  med_id: number;
  description: string;
  amount: number;
  date: string;
}

function MedicalSupplies() {
  const [items, setItems] = useState<Supply[]>([]);

  useEffect(() => {
    axios.get('/api/medical-supplies').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Medical Supplies</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="p-2 text-left">Description</th>
            <th className="p-2 text-left">Amount</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(s => (
            <tr key={s.med_id} className="border-t border-gray-700">
              <td className="p-2">{s.description}</td>
              <td className="p-2">${s.amount}</td>
              <td className="p-2">{s.date?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default MedicalSupplies;
