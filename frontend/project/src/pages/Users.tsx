import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface User {
  users_id: number;
  email: string;
  first_name: string;
  last_name: string;
  usertype: string;
  phone_number: string;
}

function Users() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/users').then(res => {
      setUsers(res.data);
    }).finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Users</h1>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <table className="w-full text-left border">
          <thead>
            <tr>
              <th className="border px-2 py-1">Email</th>
              <th className="border px-2 py-1">Name</th>
              <th className="border px-2 py-1">Role</th>
              <th className="border px-2 py-1">Phone</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.users_id} className="odd:bg-gray-100">
                <td className="border px-2 py-1">{u.email}</td>
                <td className="border px-2 py-1">{u.first_name} {u.last_name}</td>
                <td className="border px-2 py-1">{u.usertype}</td>
                <td className="border px-2 py-1">{u.phone_number}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Users;
