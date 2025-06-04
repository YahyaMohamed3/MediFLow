import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';

function ViewDetails() {
  const { patientId } = useParams();
  const [details, setDetails] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!patientId) return;
    axios.get(`/api/patients/${patientId}/details`).then(res => {
      setDetails(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [patientId]);

  if (loading) return <p className="p-4">Loading...</p>;
  if (!details) return <p className="p-4">No details found.</p>;

  return (
    <div className="p-4 space-y-4">
      <h1 className="text-2xl font-bold">Patient Details</h1>
      <div className="bg-gray-800/80 p-4 rounded">
        <pre className="whitespace-pre-wrap text-sm">{JSON.stringify(details, null, 2)}</pre>
      </div>
    </div>
  );
}

export default ViewDetails;
