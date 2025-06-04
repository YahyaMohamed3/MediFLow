import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

interface Patient { patient_id: number; name: string; }
interface Doctor { doctor_id: number; last_name: string; }

function AddAppointment() {
  const [form, setForm] = useState({
    patient_id: '',
    doctor_id: '',
    appointment_date: '',
    start_time: '',
    reason: '',
    notes: ''
  });
  const [patients, setPatients] = useState<Patient[]>([]);
  const [doctors, setDoctors] = useState<Doctor[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get('/api/patients').then(res => setPatients(res.data));
    axios.get('/api/doctors').then(res => setDoctors(res.data));
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post('/api/appointments', form);
      if (res.data.success) {
        navigate('/appointments');
      } else {
        setError(res.data.error || 'Failed to add appointment');
      }
    } catch (err) {
      setError('Failed to add appointment');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={handleSubmit} className="space-y-4 w-80">
        <h1 className="text-2xl font-bold text-center">Add Appointment</h1>
        {error && <div className="text-red-500 text-center">{error}</div>}
        <select name="patient_id" value={form.patient_id} onChange={handleChange} className="w-full border px-3 py-2 rounded" required>
          <option value="">Select Patient</option>
          {patients.map(p => (
            <option key={p.patient_id} value={p.patient_id}>{p.name}</option>
          ))}
        </select>
        <select name="doctor_id" value={form.doctor_id} onChange={handleChange} className="w-full border px-3 py-2 rounded" required>
          <option value="">Select Doctor</option>
          {doctors.map(d => (
            <option key={d.doctor_id} value={d.doctor_id}>Dr. {d.last_name}</option>
          ))}
        </select>
        <input name="appointment_date" type="date" value={form.appointment_date} onChange={handleChange} className="w-full border px-3 py-2 rounded" required />
        <input name="start_time" type="time" value={form.start_time} onChange={handleChange} className="w-full border px-3 py-2 rounded" required />
        <input name="reason" type="text" value={form.reason} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Reason" required />
        <input name="notes" type="text" value={form.notes} onChange={handleChange} className="w-full border px-3 py-2 rounded" placeholder="Notes" />
        <button type="submit" className="w-full bg-blue-600 text-white py-2 rounded disabled:opacity-50" disabled={loading}>
          {loading ? 'Saving...' : 'Save'}
        </button>
      </form>
    </div>
  );
}

export default AddAppointment;
