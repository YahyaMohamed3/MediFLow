import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Billing {
  invoice_id: number;
  patient_id: number;
  amount: number;
  payment_status: string;
  invoice_date: string;
}

function Payments() {
  const [items, setItems] = useState<Billing[]>([]);

  useEffect(() => {
    axios.get('/api/billing').then(res => setItems(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Payments</h1>
      <table className="w-full bg-gray-800/40 rounded">
        <thead>
          <tr>
            <th className="p-2 text-left">Patient</th>
            <th className="p-2 text-left">Amount</th>
            <th className="p-2 text-left">Status</th>
            <th className="p-2 text-left">Date</th>
          </tr>
        </thead>
        <tbody>
          {items.map(b => (
            <tr key={b.invoice_id} className="border-t border-gray-700">
              <td className="p-2">{b.patient_id}</td>
              <td className="p-2">${b.amount}</td>
              <td className="p-2">{b.payment_status}</td>
              <td className="p-2">{b.invoice_date?.slice(0,10)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Payments;
