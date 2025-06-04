import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';

interface Appt {
  appointmentdate: string;
  doctor: string;
  starttime: string;
  reason: string;
  confirmed: number;
}

function PatientAppointments() {
  const { patientId } = useParams();
  const [appointments, setAppointments] = useState<Appt[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!patientId) return;
    axios.get(`/api/patients/${patientId}/appointments`).then(res => {
      setAppointments(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [patientId]);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Appointments</h1>
      {loading ? <p>Loading...</p> : (
        <table className="w-full bg-gray-800/80 rounded">
          <thead>
            <tr>
              <th className="p-2 text-left">Date</th>
              <th className="p-2 text-left">Doctor</th>
              <th className="p-2 text-left">Time</th>
              <th className="p-2 text-left">Reason</th>
              <th className="p-2 text-left">Status</th>
            </tr>
          </thead>
          <tbody>
            {appointments.map((a, i) => (
              <tr key={i} className="border-t border-gray-700">
                <td className="p-2">{a.appointmentdate}</td>
                <td className="p-2">{a.doctor}</td>
                <td className="p-2">{a.starttime}</td>
                <td className="p-2">{a.reason}</td>
                <td className="p-2">{a.confirmed ? 'Confirmed' : 'Pending'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default PatientAppointments;
