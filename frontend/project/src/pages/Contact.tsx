import React from 'react';
import { motion } from 'framer-motion';
import { Mail, Phone, MapPin, Send } from 'lucide-react';
import Navbar from '../components/Navbar';

const Contact = () => {
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
          <h1 className="text-5xl font-bold text-blue-900 mb-4">Get in Touch with MediFlow</h1>
          <p className="text-xl text-blue-800/80 max-w-2xl mx-auto">
            We're here to help. Reach out to us anytime.
          </p>
        </motion.div>
      </section>

      {/* Contact Form and Info Section */}
      <section className="py-16">
        <div className="container mx-auto px-6">
          <div className="grid md:grid-cols-2 gap-12">
            {/* Contact Form */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
              className="bg-white p-8 rounded-2xl shadow-lg"
            >
              <form className="space-y-6">
                <div className="space-y-2">
                  <label htmlFor="name" className="block text-sm font-medium text-blue-900">
                    Name
                  </label>
                  <input
                    type="text"
                    id="name"
                    className="w-full px-4 py-3 rounded-lg border border-blue-200 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="Your name"
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="email" className="block text-sm font-medium text-blue-900">
                    Email
                  </label>
                  <input
                    type="email"
                    id="email"
                    className="w-full px-4 py-3 rounded-lg border border-blue-200 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="your@email.com"
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="subject" className="block text-sm font-medium text-blue-900">
                    Subject
                  </label>
                  <input
                    type="text"
                    id="subject"
                    className="w-full px-4 py-3 rounded-lg border border-blue-200 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="How can we help?"
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="message" className="block text-sm font-medium text-blue-900">
                    Message
                  </label>
                  <textarea
                    id="message"
                    rows={4}
                    className="w-full px-4 py-3 rounded-lg border border-blue-200 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="Your message..."
                  />
                </div>
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold flex items-center justify-center gap-2 hover:bg-blue-700 transition-colors"
                >
                  Send Message
                  <Send className="w-4 h-4" />
                </motion.button>
              </form>
            </motion.div>

            {/* Contact Information */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
              className="space-y-8"
            >
              <div className="bg-white p-8 rounded-2xl shadow-lg mb-8">
                <h3 className="text-2xl font-semibold text-blue-900 mb-6">Contact Information</h3>
                <div className="space-y-6">
                  <a href="tel:+18005551234" className="flex items-center gap-4 text-blue-800 hover:text-blue-600 transition-colors">
                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                      <Phone className="w-6 h-6 text-blue-600" />
                    </div>
                    <div>
                      <p className="font-medium">Phone</p>
                      <p>+1 (800) 555-1234</p>
                    </div>
                  </a>
                  <a href="mailto:support@mediflow.com" className="flex items-center gap-4 text-blue-800 hover:text-blue-600 transition-colors">
                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                      <Mail className="w-6 h-6 text-blue-600" />
                    </div>
                    <div>
                      <p className="font-medium">Email</p>
                      <p>support@mediflow.com</p>
                    </div>
                  </a>
                  <div className="flex items-center gap-4 text-blue-800">
                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                      <MapPin className="w-6 h-6 text-blue-600" />
                    </div>
                    <div>
                      <p className="font-medium">Location</p>
                      <p>123 Healthcare Ave, Medical District</p>
                      <p>San Francisco, CA 94105</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Map Placeholder */}
              <div className="bg-blue-100 h-64 rounded-2xl overflow-hidden">
                <img
                  src="https://images.pexels.com/photos/2422461/pexels-photo-2422461.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2"
                  alt="Office location"
                  className="w-full h-full object-cover"
                />
              </div>
            </motion.div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Contact;