import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Salary {
  employee: string;
  amount: number;
}

function Salaries() {
  const [salaries, setSalaries] = useState<Salary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/expenses/salaries').then(res => {
      setSalaries(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Salaries</h1>
      {loading ? <p>Loading...</p> : (
        <table className="w-full bg-gray-800/80 rounded">
          <thead>
            <tr>
              <th className="p-2 text-left">Employee</th>
              <th className="p-2 text-right">Amount</th>
            </tr>
          </thead>
          <tbody>
            {salaries.map((s, i) => (
              <tr key={i} className="border-t border-gray-700">
                <td className="p-2">{s.employee}</td>
                <td className="p-2 text-right">${s.amount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Salaries;
