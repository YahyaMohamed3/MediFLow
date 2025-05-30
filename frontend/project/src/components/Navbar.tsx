import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X } from 'lucide-react';
import { Link } from 'react-router-dom';

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.6 }}
      className="fixed w-full z-50 bg-white/80 backdrop-blur-lg shadow-sm"
    >
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between h-20">
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="flex items-center"
          >
            <Link to="/">
              <img 
                src="/[Original size] MediFLow.svg" 
                alt="MediFlow Logo" 
                className="h-[250px] w-auto mr-3"
              />
            </Link>
          </motion.div>

          {/* Desktop Menu */}
          <div className="hidden md:flex items-center space-x-8">
            <NavLink to="/">Home</NavLink>
            <NavLink to="/about">About</NavLink>
            <NavLink to="/pricing">Pricing</NavLink>
            <NavLink to="/contact">Contact</NavLink>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="bg-blue-600 text-white px-6 py-2 rounded-full font-semibold hover:bg-blue-700 transition-colors"
            >
              Get Started
            </motion.button>
          </div>

          {/* Mobile Menu Button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="text-blue-600 hover:text-blue-700"
            >
              {isOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>

        {/* Mobile Menu */}
        <AnimatePresence>
          {isOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="md:hidden"
            >
              <div className="py-4 space-y-4">
                <MobileNavLink to="/about" onClick={() => setIsOpen(false)}>About</MobileNavLink>
                <MobileNavLink to="/pricing" onClick={() => setIsOpen(false)}>Pricing</MobileNavLink>
                <MobileNavLink to="/contact" onClick={() => setIsOpen(false)}>Contact</MobileNavLink>
                <motion.button
                  whileTap={{ scale: 0.95 }}
                  className="w-full bg-blue-600 text-white px-6 py-2 rounded-full font-semibold hover:bg-blue-700 transition-colors"
                >
                  Get Started
                </motion.button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.nav>
  );
};

const NavLink = ({ to, children }: { to: string; children: React.ReactNode }) => (
  <motion.div
    whileHover={{ scale: 1.05 }}
    whileTap={{ scale: 0.95 }}
  >
    <Link
      to={to}
      className="text-blue-900 hover:text-blue-600 font-medium"
    >
      {children}
    </Link>
  </motion.div>
);

const MobileNavLink = ({ to, onClick, children }: { to: string; onClick: () => void; children: React.ReactNode }) => (
  <motion.div
    whileTap={{ scale: 0.95 }}
  >
    <Link
      to={to}
      onClick={onClick}
      className="block text-blue-900 hover:text-blue-600 font-medium text-center"
    >
      {children}
    </Link>
  </motion.div>
);

export default Navbar;