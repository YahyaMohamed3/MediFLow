import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';

interface Slot {
  day: string;
  start_time: string;
  end_time: string;
}

function Schedule() {
  const { doctorId } = useParams();
  const [slots, setSlots] = useState<Slot[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!doctorId) return;
    axios.get(`/api/schedule/${doctorId}`).then(res => {
      setSlots(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [doctorId]);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Schedule</h1>
      {loading ? <p>Loading...</p> : (
        <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
          {slots.map((slot, i) => (
            <div key={i} className="bg-gray-800/80 p-4 rounded shadow">
              <h2 className="font-semibold">{slot.day}</h2>
              <p className="text-sm">{slot.start_time} - {slot.end_time}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default Schedule;
