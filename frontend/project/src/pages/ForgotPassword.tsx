import React, { useState } from 'react';
import axios from 'axios';

function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await axios.post('/api/forgot', { email });
    setMsg(res.data.message || 'Check your email');
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={submit} className="space-y-4 w-80">
        <h1 className="text-2xl font-bold text-center">Forgot Password</h1>
        <input type="email" value={email} onChange={e=>setEmail(e.target.value)} className="w-full border px-3 py-2 rounded" required />
        <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded">Submit</button>
        {msg && <div className="text-center mt-2">{msg}</div>}
      </form>
    </div>
  );
}

export default ForgotPassword;
