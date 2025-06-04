import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Equipment {
  equipment_id: number;
  description: string;
  amount: number;
  date: string;
}

function Equipments() {
  const [items, setItems] = useState<Equipment[]>([]);

  useEffect(() => {
    axios.get('/api/equipments').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Equipments</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="p-2 text-left">Description</th>
            <th className="p-2 text-left">Amount</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(e => (
            <tr key={e.equipment_id} className="border-t border-gray-700">
              <td className="p-2">{e.description}</td>
              <td className="p-2">${e.amount}</td>
              <td className="p-2">{e.date?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Equipments;
