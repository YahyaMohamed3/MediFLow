import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Register() {
  const [form, setForm] = useState({
    email: '',
    firstName: '',
    lastName: '',
    password: '',
    confirmPassword: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post('/api/register', {
        email: form.email,
        first_name: form.firstName,
        last_name: form.lastName,
        password: form.password,
        confirm_password: form.confirmPassword
      });
      if (res.data.success) {
        navigate('/login');
      } else {
        setError(res.data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={handleSubmit} className="space-y-4 w-80">
        <h1 className="text-2xl font-bold text-center">Register</h1>
        {error && <div className="text-red-500 text-center">{error}</div>}
        <input
          name="email"
          type="email"
          value={form.email}
          onChange={handleChange}
          className="w-full border px-3 py-2 rounded"
          placeholder="Email"
          required
        />
        <input
          name="firstName"
          type="text"
          value={form.firstName}
          onChange={handleChange}
          className="w-full border px-3 py-2 rounded"
          placeholder="First name"
          required
        />
        <input
          name="lastName"
          type="text"
          value={form.lastName}
          onChange={handleChange}
          className="w-full border px-3 py-2 rounded"
          placeholder="Last name"
          required
        />
        <input
          name="password"
          type="password"
          value={form.password}
          onChange={handleChange}
          className="w-full border px-3 py-2 rounded"
          placeholder="Password"
          required
        />
        <input
          name="confirmPassword"
          type="password"
          value={form.confirmPassword}
          onChange={handleChange}
          className="w-full border px-3 py-2 rounded"
          placeholder="Confirm password"
          required
        />
        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 rounded disabled:opacity-50"
          disabled={loading}
        >
          {loading ? 'Registering...' : 'Register'}
        </button>
      </form>
    </div>
  );
}

export default Register;
