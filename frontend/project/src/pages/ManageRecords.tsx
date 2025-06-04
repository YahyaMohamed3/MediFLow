import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';

interface Record {
  visit_date: string;
  diagnosis: string;
  test_name: string;
  test_result: string;
  reference_range: string;
  test_date: string;
  follow_up_instructions: string;
}

function ManageRecords() {
  const { patientId } = useParams();
  const [records, setRecords] = useState<Record[]>([]);

  useEffect(() => {
    axios.get(`/api/doctor/records/${patientId}`).then(res => setRecords(res.data));
  }, [patientId]);

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-xl font-bold">Medical Records</h1>
      <ul className="space-y-2">
        {records.map((r, idx) => (
          <li key={idx} className="border-b border-gray-700 pb-2">
            <p>{r.visit_date} - {r.diagnosis}</p>
            {r.test_name && <p className="text-sm">{r.test_name}: {r.test_result} ({r.reference_range})</p>}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default ManageRecords;
