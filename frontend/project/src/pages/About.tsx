import React from 'react';
import { motion } from 'framer-motion';
import { Award, Heart, Zap, Shield, Users, Github, Linkedin, Twitter } from 'lucide-react';
import Navbar from '../components/Navbar';

const About = () => {
  const coreValues = [
    {
      icon: Heart,
      title: "Patient-Centric",
      description: "Everything we do is focused on improving patient care and experience."
    },
    {
      icon: Zap,
      title: "Innovation",
      description: "Constantly pushing boundaries with cutting-edge healthcare technology."
    },
    {
      icon: Shield,
      title: "Security",
      description: "Unwavering commitment to protecting sensitive medical data."
    },
    {
      icon: Users,
      title: "Collaboration",
      description: "Building strong partnerships with healthcare providers worldwide."
    }
  ];

  const teamMembers = [
    {  
      name: "Dr. Michael Rodriguez",
      role: "CEO & Co-founder",
      image: "https://images.pexels.com/photos/5452293/pexels-photo-5452293.jpeg?auto=compress&cs=tinysrgb&w=300",
      bio: "Former physician with 15 years of healthcare technology experience."
    },
    {
      name: "Dr. Sarah Williams",
      role: "CTO",
      image: "https://images.pexels.com/photos/5452201/pexels-photo-5452201.jpeg?auto=compress&cs=tinysrgb&w=300",
      bio: "AI expert with a passion for healthcare innovation."
    },
    {
      name: "Emily Thompson",
      role: "Head of Product",
      image: "https://images.pexels.com/photos/5407206/pexels-photo-5407206.jpeg?auto=compress&cs=tinysrgb&w=300",
      bio: "Product leader focused on creating intuitive healthcare solutions."
    }
  ];

  const milestones = [
    {
      year: "2020",
      title: "MediFlow Founded",
      description: "Started with a vision to revolutionize healthcare management."
    },
    {
      year: "2021",
      title: "First Major Release",
      description: "Launched our core platform serving 50+ clinics."
    },
    {
      year: "2022",
      title: "AI Integration",
      description: "Introduced AI-powered scheduling and patient communication."
    },
    {
      year: "2023",
      title: "Global Expansion",
      description: "Expanded to serve 500+ clinics worldwide."
    }
  ];

  return (
    <div className="min-h-screen bg-white">
      <Navbar />
      
      {/* Hero Section */}
      <section className="pt-32 pb-16 bg-gradient-to-b from-blue-50 to-white">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="container mx-auto px-6 text-center"
        >
          <h1 className="text-5xl font-bold text-blue-900 mb-4">Our Mission at MediFlow</h1>
          <p className="text-xl text-blue-800/80 max-w-2xl mx-auto">
            Revolutionizing healthcare management with intelligent solutions that empower medical professionals to focus on what matters most: patient care.
          </p>
        </motion.div>
      </section>

      {/* Core Values Section */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <motion.h2 
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl font-bold text-blue-900 text-center mb-12"
          >
            Our Core Values
          </motion.h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {coreValues.map((value, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="bg-white p-6 rounded-2xl shadow-lg text-center"
              >
                <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <value.icon className="w-8 h-8 text-blue-600" />
                </div>
                <h3 className="text-xl font-semibold text-blue-900 mb-2">{value.title}</h3>
                <p className="text-blue-800/70">{value.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Timeline Section */}
      <section className="py-20 bg-gray-50">
        <div className="container mx-auto px-6">
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl font-bold text-blue-900 text-center mb-12"
          >
            Our Journey
          </motion.h2>
          <div className="max-w-3xl mx-auto">
            {milestones.map((milestone, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: index % 2 === 0 ? -20 : 20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="flex items-start gap-8 mb-12"
              >
                <div className="w-24 flex-shrink-0 text-right">
                  <span className="text-xl font-bold text-blue-600">{milestone.year}</span>
                </div>
                <div className="flex-grow">
                  <div className="bg-white p-6 rounded-2xl shadow-lg">
                    <h3 className="text-xl font-semibold text-blue-900 mb-2">{milestone.title}</h3>
                    <p className="text-blue-800/70">{milestone.description}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl font-bold text-blue-900 text-center mb-12"
          >
            Meet Our Team
          </motion.h2>
          <div className="grid md:grid-cols-3 gap-8">
            {teamMembers.map((member, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="bg-white p-6 rounded-2xl shadow-lg text-center group"
              >
                <div className="relative w-32 h-32 mx-auto mb-4">
                  <img
                    src={member.image}
                    alt={member.name}
                    className="w-full h-full object-cover rounded-full"
                  />
                  <div className="absolute inset-0 bg-blue-600/80 rounded-full opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-4">
                    <a href="#" className="text-white hover:text-blue-200 transition-colors">
                      <Linkedin className="w-5 h-5" />
                    </a>
                    <a href="#" className="text-white hover:text-blue-200 transition-colors">
                      <Twitter className="w-5 h-5" />
                    </a>
                    <a href="#" className="text-white hover:text-blue-200 transition-colors">
                      <Github className="w-5 h-5" />
                    </a>
                  </div>
                </div>
                <h3 className="text-xl font-semibold text-blue-900 mb-1">{member.name}</h3>
                <p className="text-blue-600 mb-2">{member.role}</p>
                <p className="text-blue-800/70">{member.bio}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-blue-600">
        <div className="container mx-auto px-6 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-2xl mx-auto"
          >
            <h2 className="text-3xl font-bold text-white mb-4">
              Join us on our mission
            </h2>
            <p className="text-blue-100 mb-8">
              Contact us today to learn more about how MediFlow can transform your healthcare practice.
            </p>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="bg-white text-blue-600 px-8 py-3 rounded-full font-semibold hover:bg-blue-50 transition-colors"
            >
              Get Started Today
            </motion.button>
          </motion.div>
        </div>
      </section>
    </div>
  );
};

export default About;