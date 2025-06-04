import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Expense {
  category: string;
  amount: number;
}

function Expenses() {
  const [expenses, setExpenses] = useState<Expense[]>([]);
  useEffect(() => {
    axios.get('/api/expenses').then(res => setExpenses(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Expenses</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="text-left p-2">Category</th>
            <th className="text-left p-2">Amount</th>
          </tr>
        </thead>
        <tbody>
          {expenses.map((e, i) => (
            <tr key={i} className="border-t border-gray-700">
              <td className="p-2">{e.category}</td>
              <td className="p-2">${e.amount}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Expenses;
