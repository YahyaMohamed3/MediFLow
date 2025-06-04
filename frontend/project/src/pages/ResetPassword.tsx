import React, { useState } from 'react';
import axios from 'axios';
import { useSearchParams } from 'react-router-dom';

function ResetPassword() {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState('');
  const [params] = useSearchParams();
  const token = params.get('token');
  const email = params.get('email');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) { setMsg('Passwords do not match'); return; }
    const res = await axios.post('/api/reset', { token, email, password });
    if (res.data.success) setMsg('Password reset');
    else setMsg(res.data.error || 'Failed');
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={submit} className="space-y-4 w-80">
        <h1 className="text-2xl font-bold text-center">Reset Password</h1>
        <input type="password" value={password} onChange={e=>setPassword(e.target.value)} className="w-full border px-3 py-2 rounded" placeholder="New Password" required />
        <input type="password" value={confirm} onChange={e=>setConfirm(e.target.value)} className="w-full border px-3 py-2 rounded" placeholder="Confirm Password" required />
        <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded">Reset</button>
        {msg && <div className="text-center mt-2">{msg}</div>}
      </form>
    </div>
  );
}

export default ResetPassword;
