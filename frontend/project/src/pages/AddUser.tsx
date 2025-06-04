import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function AddUser() {
  const [form, setForm] = useState({
    email: '',
    first_name: '',
    last_name: '',
    password: '',
    usertype: '',
    phone: '',
    payroll: ''
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
      const res = await axios.post('/api/users', form);
      if (res.data.success) {
        navigate('/users');
      } else {
        setError(res.data.error || 'Failed to add user');
      }
    } catch (err) {
      setError('Failed to add user');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={handleSubmit} className="space-y-4 w-80">
        <h1 className="text-2xl font-bold text-center">Add User</h1>
        {error && <div className="text-red-500 text-center">{error}</div>}
        <input name="email" type="email" value={form.email} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Email" required />
        <input name="first_name" type="text" value={form.first_name} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="First name" required />
        <input name="last_name" type="text" value={form.last_name} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Last name" required />
        <input name="phone" type="tel" value={form.phone} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Phone" />
        <select name="usertype" value={form.usertype} onChange={handleChange} className="w-full border px-3 py-2 rounded" required>
          <option value="">Select Role</option>
          <option value="Receptionist">Receptionist</option>
          <option value="Nurse">Nurse</option>
          <option value="Medical Assistant">Medical Assistant</option>
        </select>
        <input name="payroll" type="number" value={form.payroll} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Payroll" />
        <input name="password" type="password" value={form.password} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Password" required />
        <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded disabled:opacity-50" disabled={loading}>
          {loading ? 'Saving...' : 'Save'}
        </button>
      </form>
    </div>
  );
}

export default AddUser;
