import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { motion } from 'framer-motion';

function Analytics() {
  const [data, setData] = useState<Record<string, number>>({});
  useEffect(() => {
    axios.get('/api/analytics').then(res => setData(res.data));
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl mb-4">Analytics</h1>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {Object.entries(data).map(([label, value]) => (
          <motion.div
            key={label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-gray-800/40 backdrop-blur rounded p-4 text-center"
          >
            <h2 className="text-lg mb-1">{label}</h2>
            <p className="text-3xl font-bold">{value.toFixed(1)}%</p>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

export default Analytics;
