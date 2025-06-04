import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface OtherExpense {
  other_expenses_id: number;
  description: string;
  amount: number;
  date: string;
}

function OtherExpenses() {
  const [items, setItems] = useState<OtherExpense[]>([]);

  useEffect(() => {
    axios.get('/api/other-expenses').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Other Expenses</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="p-2 text-left">Description</th>
            <th className="p-2 text-left">Amount</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(o => (
            <tr key={o.other_expenses_id} className="border-t border-gray-700">
              <td className="p-2">{o.description}</td>
              <td className="p-2">${o.amount}</td>
              <td className="p-2">{o.date?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default OtherExpenses;
