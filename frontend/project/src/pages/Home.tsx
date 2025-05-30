import { motion, useScroll, useTransform } from 'framer-motion';
import { Calendar, Users, Brain, ChevronRight, FileText, MessageSquare, DollarSign, Award, Star, Phone, Check, Shield, Zap, Heart } from 'lucide-react';
import Navbar from '../components/Navbar';
import FeatureCard from '../components/FeatureCard';
import TestimonialCard from '../components/TestimonialCard';

function Home() {
  const { scrollYProgress } = useScroll();
  const opacity = useTransform(scrollYProgress, [0, 0.2], [1, 0]);

  const features = [
    {
      title: "Smart Scheduling",
      description: "Intelligent appointment booking with conflict detection and automated reminders",
      icon: Calendar,
      details: ["Doctor availability management", "Automated patient reminders", "Real-time calendar sync"]
    },
    {
      title: "Patient Management",
      description: "Complete patient profiles with digital medical records and history tracking",
      icon: Users,
      details: ["Digital medical records", "Insurance tracking", "Emergency contact management"]
    },
    {
      title: "Clinical Workflow",
      description: "Streamlined clinical processes with electronic prescriptions and documentation",
      icon: FileText,
      details: ["Electronic prescriptions", "Diagnosis documentation", "Secure document sharing"]
    },
    {
      title: "Financial Management",
      description: "Automated billing and comprehensive financial analytics",
      icon: DollarSign,
      details: ["Automated invoicing", "Insurance claims", "Revenue analytics"]
    },
    {
      title: "Communication Hub",
      description: "Secure messaging and real-time collaboration tools",
      icon: MessageSquare,
      details: ["Encrypted messaging", "Real-time notifications", "Team collaboration"]
    }
  ];

  const whyChooseFeatures = [
    {
      title: "Enterprise Security",
      description: "HIPAA-compliant with end-to-end encryption and advanced security protocols to protect patient data.",
      icon: Shield
    },
    {
      title: "Lightning Fast",
      description: "Optimized performance with cloud infrastructure ensuring quick response times and minimal downtime.",
      icon: Zap
    },
    {
      title: "Patient-Centered Care",
      description: "Designed with patient experience in mind, enabling better care coordination and communication.",
      icon: Heart
    }
  ];

  const pricingPlans = [
    {
      name: "Starter",
      description: "Perfect for small practices",
      price: "$99",
      period: "month",
      popular: false,
      cta: "Start Free Trial",
      features: [
        "Up to 5 users",
        "500 patient records",
        "Basic scheduling",
        "Email support",
        "Mobile app access"
      ]
    },
    {
      name: "Professional",
      description: "Ideal for growing practices",
      price: "$199",
      period: "month",
      popular: true,
      cta: "Get Started",
      features: [
        "Up to 25 users",
        "Unlimited patient records",
        "Advanced scheduling",
        "Priority support",
        "AI assistant",
        "Custom reports",
        "Integrations"
      ]
    },
    {
      name: "Enterprise",
      description: "For large healthcare organizations",
      price: "Custom",
      period: "contact us",
      popular: false,
      cta: "Contact Sales",
      features: [
        "Unlimited users",
        "Multi-location support",
        "Advanced analytics",
        "24/7 phone support",
        "Custom integrations",
        "Dedicated account manager",
        "Training & onboarding"
      ]
    }
  ];

  const valueProps = [
    {
      title: "For Clinic Administrators",
      benefits: [
        "Reduce administrative workload by 70%",
        "Complete clinic oversight in one dashboard",
        "Real-time financial tracking and reporting"
      ],
      icon: Award
    },
    {
      title: "For Doctors",
      benefits: [
        "Focus on patient care, not paperwork",
        "Instant access to patient history",
        "Streamlined prescription workflow"
      ],
      icon: Brain
    },
    {
      title: "For Receptionists",
      benefits: [
        "Effortless appointment scheduling",
        "Quick patient check-in",
        "Automated reminder system"
      ],
      icon: Phone
    }
  ];

  const testimonials = [
    {
      name: "Dr. Michael Chen",
      role: "Medical Director",
      content: "MediFlow has transformed how we manage our clinic. The efficiency gains are remarkable.",
      image: "https://images.pexels.com/photos/5452293/pexels-photo-5452293.jpeg?auto=compress&cs=tinysrgb&w=300"
    },
    {
      name: "Dr. Sarah Johnson",
      role: "Pediatrician",
      content: "The patient management system is intuitive and has greatly improved our daily operations.",
      image: "https://images.pexels.com/photos/5452201/pexels-photo-5452201.jpeg?auto=compress&cs=tinysrgb&w=300"
    },
    {
      name: "Dr. Emily Rodriguez",
      role: "Family Physician",
      content: "The AI assistant has revolutionized our patient scheduling and communication.",
      image: "https://images.pexels.com/photos/5407206/pexels-photo-5407206.jpeg?auto=compress&cs=tinysrgb&w=300"
    }
  ];

  const stats = [
    { label: "Clinics Served", value: "500+" },
    { label: "Patient Records", value: "1M+" },
    { label: "Monthly Appointments", value: "50K+" },
    { label: "Staff Satisfaction", value: "98%" }
  ];

  return (
    <div className="min-h-screen bg-white">
      <Navbar />
      
      {/* Hero Section */}
      <section className="relative h-screen flex items-center justify-center overflow-hidden">
        <motion.div 
          className="absolute inset-0 z-0"
          style={{ opacity }}
        >
          <div className="absolute inset-0 bg-blue-500/10" />
          <img 
            src="https://images.pexels.com/photos/7579831/pexels-photo-7579831.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2"
            alt="Medical background"
            className="w-full h-full object-cover"
          />
        </motion.div>

        <div className="container mx-auto px-6 relative z-10">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            <h1 className="text-5xl md:text-6xl font-bold text-blue-900 mb-6">
              Complete Healthcare Management Made Simple
            </h1>
            <p className="text-xl text-blue-800 mb-8 max-w-2xl mx-auto">
              Streamline your clinic operations with MediFlow - the all-in-one solution for patient care, appointments, billing, and medical records.
            </p>
            <div className="flex gap-4 justify-center">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="bg-blue-600 text-white px-8 py-4 rounded-full text-lg font-semibold flex items-center gap-2 hover:bg-blue-700 transition-colors"
              >
                Get Started Free
                <ChevronRight className="w-5 h-5" />
              </motion.button>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="bg-white text-blue-600 px-8 py-4 rounded-full text-lg font-semibold flex items-center gap-2 hover:bg-blue-50 transition-colors border-2 border-blue-600"
              >
                Schedule Demo
                <ChevronRight className="w-5 h-5" />
              </motion.button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-gray-50">
        <div className="container mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-blue-900 mb-4">
              Powerful Features for Modern Healthcare
            </h2>
            <p className="text-lg text-blue-800/80 max-w-2xl mx-auto">
              Everything you need to manage your clinic efficiently in one integrated platform
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <FeatureCard key={index} {...feature} index={index} />
            ))}
          </div>
        </div>
      </section>

      {/* Value Propositions */}
      <section className="py-20 bg-white">
        <div className="container mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-blue-900 mb-4">
              Tailored for Your Role
            </h2>
            <p className="text-lg text-blue-800/80 max-w-2xl mx-auto">
              Discover how MediFlow enhances efficiency for every team member
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {valueProps.map((prop, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="bg-white p-8 rounded-2xl shadow-lg hover:shadow-xl transition-shadow"
              >
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-6">
                  <prop.icon className="w-6 h-6 text-blue-600" />
                </div>
                <h3 className="text-xl font-semibold text-blue-900 mb-4">{prop.title}</h3>
                <ul className="space-y-3">
                  {prop.benefits.map((benefit, i) => (
                    <li key={i} className="flex items-start gap-2 text-blue-800/70">
                      <Star className="w-5 h-5 text-blue-600 flex-shrink-0 mt-1" />
                      <span>{benefit}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* AI Feature Highlight */}
      <section className="py-20 bg-gradient-to-r from-blue-600 to-blue-800 text-white">
        <div className="container mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center max-w-4xl mx-auto"
          >
            <h2 className="text-4xl font-bold mb-6">
              Introducing our cutting-edge AI Assistant
            </h2>
            <p className="text-xl mb-8 opacity-90">
              Multilingual voice and text-based patient interaction for appointment booking, record access, and inquiries
            </p>
            <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 mt-12">
              <div className="aspect-video rounded-lg overflow-hidden bg-black/20">
                <video
                  className="w-full h-full object-cover rounded-lg"
                  controls
                  preload="metadata"
                  poster="/Thumbnail.png"
                >
                  <source src="/demo.mp4" type="video/mp4" />
                  <p className="text-lg text-center p-8">
                    Your browser does not support the video tag. 
                    <a href="/demo.mp4" className="text-blue-300 underline ml-2">
                      Download the demo video
                    </a>
                  </p>
                </video>
              </div>
              <div className="mt-6 text-center">
                <p className="text-lg opacity-90 mb-4">
                  Watch how our AI assistant handles real patient interactions
                </p>
                <div className="flex flex-wrap justify-center gap-4 text-sm opacity-80">
                  <span>✓ Multilingual Support</span>
                  <span>✓ Voice Recognition</span>
                  <span>✓ Smart Scheduling</span>
                  <span>✓ Patient Records Access</span>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Why Choose MediFlow Section */}
      <section className="py-20 bg-white">
        <div className="container mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-blue-900 mb-4">
              Why Choose MediFlow?
            </h2>
            <p className="text-lg text-blue-800/80 max-w-2xl mx-auto">
              MediFlow transforms healthcare management into a seamless experience with AI-driven features and unparalleled ease of use.
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {whyChooseFeatures.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                whileHover={{ scale: 1.05 }}
                className="bg-white p-8 rounded-2xl shadow-lg hover:shadow-xl transition-all"
              >
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-6">
                  <feature.icon className="w-6 h-6 text-blue-600" />
                </div>
                <h3 className="text-xl font-semibold text-blue-900 mb-4">{feature.title}</h3>
                <p className="text-blue-800/70">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 bg-gradient-to-b from-gray-50 to-white">
        <div className="container mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-blue-900 mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-lg text-blue-800/80 max-w-2xl mx-auto">
              Choose the perfect plan for your healthcare practice
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {pricingPlans.map((plan, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className={`bg-white p-8 rounded-2xl shadow-lg hover:shadow-xl transition-all relative ${
                  plan.popular ? 'border-2 border-blue-600' : ''
                }`}
              >
                {plan.popular && (
                  <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2">
                    <span className="bg-blue-600 text-white px-4 py-1 rounded-full text-sm font-semibold">
                      Most Popular
                    </span>
                  </div>
                )}
                <div className="text-center mb-8">
                  <h3 className="text-xl font-semibold text-blue-900 mb-2">{plan.name}</h3>
                  <p className="text-blue-800/70 mb-4">{plan.description}</p>
                  <div className="flex items-baseline justify-center">
                    <span className="text-4xl font-bold text-blue-900">{plan.price}</span>
                    <span className="text-blue-800/70 ml-2">/{plan.period}</span>
                  </div>
                </div>
                <ul className="space-y-4 mb-8">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-start gap-2 text-blue-800/70">
                      <Check className="w-5 h-5 text-blue-600 flex-shrink-0 mt-1" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className={`w-full py-3 rounded-full font-semibold transition-colors ${
                    plan.popular
                      ? 'bg-blue-600 text-white hover:bg-blue-700'
                      : 'bg-blue-100 text-blue-600 hover:bg-blue-200'
                  }`}
                >
                  {plan.cta}
                </motion.button>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-20 bg-gray-50">
        <div className="container mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl font-bold text-blue-900 mb-4">
              Trusted by Healthcare Professionals
            </h2>
            <p className="text-lg text-blue-800/80 max-w-2xl mx-auto">
              See what medical professionals are saying about MediFlow
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <TestimonialCard key={index} {...testimonial} index={index} />
            ))}
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mt-16">
            {stats.map((stat, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="text-center"
              >
                <div className="text-4xl font-bold text-blue-600 mb-2">{stat.value}</div>
                <div className="text-blue-800/70">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-blue-900 text-white py-12">
        <div className="container mx-auto px-6">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <h3 className="text-xl font-semibold mb-4">MediFlow</h3>
              <p className="text-blue-200">Transforming healthcare management for the digital age</p>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-blue-200">
                <li>Features</li>
                <li>Pricing</li>
                <li>Security</li>
                <li>Enterprise</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Company</h4>
              <ul className="space-y-2 text-blue-200">
                <li>About</li>
                <li>Careers</li>
                <li>Blog</li>
                <li>Contact</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Connect</h4>
              <ul className="space-y-2 text-blue-200">
                <li>Twitter</li>
                <li>LinkedIn</li>
                <li>Facebook</li>
                <li>Instagram</li>
              </ul>
            </div>
          </div>
          <div className="border-t border-blue-800 mt-8 pt-8 text-center text-blue-200">
            <p>&copy; 2025 MediFlow. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default Home;
