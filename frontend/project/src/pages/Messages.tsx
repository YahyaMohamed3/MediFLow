import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Message {
  sender_id: number;
  sender_user_type: string;
  receiver_id: number;
  receiver_user_type: string;
  message: string;
  timestamp: string;
}

function Messages() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [receiver, setReceiver] = useState('');
  const [receiverType, setReceiverType] = useState('Doctor');
  const [text, setText] = useState('');

  const fetchMessages = () => {
    axios.get('/api/messages').then(res => setMessages(res.data));
  };

  useEffect(() => {
    fetchMessages();
  }, []);

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    await axios.post('/api/messages', {
      receiver_id: receiver,
      receiver_user_type: receiverType,
      message: text
    });
    setText('');
    fetchMessages();
  };

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-2xl">Messages</h1>
      <form onSubmit={send} className="space-y-2">
        <input value={receiver} onChange={e=>setReceiver(e.target.value)} placeholder="Receiver ID" className="border w-full px-3 py-2 rounded" required />
        <select value={receiverType} onChange={e=>setReceiverType(e.target.value)} className="border w-full px-3 py-2 rounded">
          <option value="Doctor">Doctor</option>
          <option value="Receptionist">Receptionist</option>
          <option value="admin">Admin</option>
        </select>
        <textarea value={text} onChange={e=>setText(e.target.value)} className="border w-full px-3 py-2 rounded" required />
        <button type="submit" className="bg-blue-600 text-white px-4 py-2 rounded">Send</button>
      </form>
      <ul className="space-y-2">
        {messages.map((m, i) => (
          <li key={i} className="bg-gray-800/40 rounded p-2">
            <div className="text-sm opacity-70">{m.sender_user_type} #{m.sender_id} → {m.receiver_user_type} #{m.receiver_id}</div>
            <div>{m.message}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default Messages;
