import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';

interface Prescription {
  prescription_id: number;
  medication: string;
  dosage: string;
  instructions: string;
  date_prescribed: string;
}

function ManagePrescriptions() {
  const { patientId } = useParams();
  const [items, setItems] = useState<Prescription[]>([]);
  const [form, setForm] = useState({ medication: '', dosage: '', instructions: '' });

  useEffect(() => {
    axios.get(`/api/doctor/prescriptions/${patientId}`).then(res => setItems(res.data));
  }, [patientId]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await axios.post(`/api/doctor/prescriptions/${patientId}`, form);
    const res = await axios.get(`/api/doctor/prescriptions/${patientId}`);
    setItems(res.data);
    setForm({ medication: '', dosage: '', instructions: '' });
  };

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-xl font-bold">Manage Prescriptions</h1>
      <form onSubmit={handleSubmit} className="space-y-2">
        <input name="medication" value={form.medication} onChange={handleChange} placeholder="Medication" className="w-full px-3 py-2 rounded bg-gray-800" />
        <input name="dosage" value={form.dosage} onChange={handleChange} placeholder="Dosage" className="w-full px-3 py-2 rounded bg-gray-800" />
        <input name="instructions" value={form.instructions} onChange={handleChange} placeholder="Instructions" className="w-full px-3 py-2 rounded bg-gray-800" />
        <button type="submit" className="px-4 py-2 bg-blue-600 rounded">Add</button>
      </form>
      <ul className="space-y-2">
        {items.map(p => (
          <li key={p.prescription_id} className="border-b border-gray-700 pb-2">
            <strong>{p.medication}</strong> - {p.dosage} ({p.date_prescribed})
            <p className="text-sm opacity-80">{p.instructions}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default ManagePrescriptions;
