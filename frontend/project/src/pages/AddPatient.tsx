import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function AddPatient() {
  const [form, setForm] = useState({
    first_name: '',
    last_name: '',
    date_of_birth: '',
    gender: '',
    address: '',
    phone: '',
    email: '',
    insurance: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post('/api/patients', form);
      if (res.data.success) {
        navigate('/patients');
      } else {
        setError(res.data.error || 'Failed to add patient');
      }
    } catch (err) {
      setError('Failed to add patient');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={handleSubmit} className="space-y-4 w-80">
        <h1 className="text-2xl font-bold text-center">Add Patient</h1>
        {error && <div className="text-red-500 text-center">{error}</div>}
        <input name="first_name" type="text" value={form.first_name} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="First name" required />
        <input name="last_name" type="text" value={form.last_name} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Last name" required />
        <input name="date_of_birth" type="date" value={form.date_of_birth} onChange={handleChange} className="w-full border px-3 py-2 rounded" required />
        <select name="gender" value={form.gender} onChange={handleChange} className="w-full border px-3 py-2 rounded" required>
          <option value="">Gender</option>
          <option value="Male">Male</option>
          <option value="Female">Female</option>
          <option value="Other">Other</option>
        </select>
        <input name="phone" type="tel" value={form.phone} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Phone" />
        <input name="email" type="email" value={form.email} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Email" required />
        <input name="address" type="text" value={form.address} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Address" required />
        <input name="insurance" type="text" value={form.insurance} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Insurance" />
        <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded disabled:opacity-50" disabled={loading}>
          {loading ? 'Saving...' : 'Save'}
        </button>
      </form>
    </div>
  );
}

export default AddPatient;
