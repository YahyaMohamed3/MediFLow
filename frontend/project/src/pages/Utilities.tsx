import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Utility {
  utility_id: number;
  description: string;
  amount: number;
  date: string;
}

function Utilities() {
  const [items, setItems] = useState<Utility[]>([]);

  useEffect(() => {
    axios.get('/api/utilities').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Utilities</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="p-2 text-left">Description</th>
            <th className="p-2 text-left">Amount</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(u => (
            <tr key={u.utility_id} className="border-t border-gray-700">
              <td className="p-2">{u.description}</td>
              <td className="p-2">${u.amount}</td>
              <td className="p-2">{u.date?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Utilities;
