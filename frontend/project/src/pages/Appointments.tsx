import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Appointment {
  AppointmentID: number;
  AppointmentDate: string;
  StartTime: string;
  Reason: string;
  confirmed: number;
  patient_name: string;
  doctor_name: string;
}

function Appointments() {
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get('/api/appointments').then(res => {
      setAppointments(res.data);
    }).finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Appointments</h1>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <table className="w-full text-left border">
          <thead>
            <tr>
              <th className="border px-2 py-1">Date</th>
              <th className="border px-2 py-1">Time</th>
              <th className="border px-2 py-1">Patient</th>
              <th className="border px-2 py-1">Doctor</th>
              <th className="border px-2 py-1">Reason</th>
            </tr>
          </thead>
          <tbody>
            {appointments.map(a => (
              <tr key={a.AppointmentID} className="odd:bg-gray-100">
                <td className="border px-2 py-1">{a.AppointmentDate}</td>
                <td className="border px-2 py-1">{a.StartTime}</td>
                <td className="border px-2 py-1">{a.patient_name}</td>
                <td className="border px-2 py-1">{a.doctor_name}</td>
                <td className="border px-2 py-1">{a.Reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Appointments;
