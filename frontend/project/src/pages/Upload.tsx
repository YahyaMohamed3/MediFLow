import React, { useState } from 'react';
import axios from 'axios';

function Upload() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    const res = await axios.post('/api/upload', formData);
    if (res.data.success) setMessage('Uploaded successfully');
    else setMessage(res.data.error || 'Upload failed');
  };

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Upload</h1>
      <form onSubmit={submit} className="space-y-2">
        <input type="file" onChange={e => setFile(e.target.files?.[0] || null)} />
        <button type="submit" className="bg-blue-600 text-white px-4 py-2 rounded">Upload</button>
      </form>
      {message && <div className="mt-2">{message}</div>}
    </div>
  );
}

export default Upload;
