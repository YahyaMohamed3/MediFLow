import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface MarketingItem {
  marketing_id: number;
  description: string;
  amount: number;
  date: string;
}

function Marketing() {
  const [items, setItems] = useState<MarketingItem[]>([]);

  useEffect(() => {
    axios.get('/api/marketing').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Marketing</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="p-2 text-left">Description</th>
            <th className="p-2 text-left">Amount</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(m => (
            <tr key={m.marketing_id} className="border-t border-gray-700">
              <td className="p-2">{m.description}</td>
              <td className="p-2">${m.amount}</td>
              <td className="p-2">{m.date?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Marketing;
