import React from 'react';
import { motion } from 'framer-motion';

interface TestimonialCardProps {
  name: string;
  role: string;
  content: string;
  image: string;
  index: number;
}

const TestimonialCard = ({ name, role, content, image, index }: TestimonialCardProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5, delay: index * 0.1 }}
      className="bg-white p-6 rounded-2xl shadow-lg hover:shadow-xl transition-shadow"
    >
      <div className="flex items-center mb-4">
        <img
          src={image}
          alt={name}
          className="w-12 h-12 rounded-full object-cover mr-4"
        />
        <div>
          <h4 className="text-lg font-semibold text-blue-900">{name}</h4>
          <p className="text-blue-800/70">{role}</p>
        </div>
      </div>
      <p className="text-blue-800/80 italic">&ldquo;{content}&rdquo;</p>
    </motion.div>
  );
};

export default TestimonialCard;