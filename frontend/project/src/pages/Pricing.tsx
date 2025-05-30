import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, X } from 'lucide-react';
import Navbar from '../components/Navbar';

const Pricing = () => {
  const [isAnnual, setIsAnnual] = useState(false);

  const plans = [
    {
      name: "Starter",
      price: isAnnual ? 0 : 0,
      period: isAnnual ? "year" : "month",
      description: "Perfect for small clinics just getting started",
      features: [
        "Up to 100 patient records",
        "Basic appointment scheduling",
        "Standard support",
        "Essential reports"
      ],
      cta: "Start Free",
      popular: false
    },
    {
      name: "Professional",
      price: isAnnual ? 470 : 49,
      period: isAnnual ? "year" : "month",
      description: "Ideal for growing medical practices",
      features: [
        "Unlimited patient records",
        "Advanced scheduling with AI",
        "Priority support",
        "Advanced analytics",
        "Custom branding"
      ],
      cta: "Start 14-Day Trial",
      popular: true
    },
    {
      name: "Enterprise",
      price: isAnnual ? 950 : 99,
      period: isAnnual ? "year" : "month",
      description: "For large clinics and hospitals",
      features: [
        "Multi-location support",
        "Custom AI training",
        "24/7 dedicated support",
        "Advanced security features",
        "API access"
      ],
      cta: "Contact Sales",
      popular: false
    }
  ];

  const featureComparison = [
    {
      feature: "Patient Records",
      starter: "Up to 100",
      professional: "Unlimited",
      enterprise: "Unlimited"
    },
    {
      feature: "Appointment Scheduling",
      starter: "Basic",
      professional: "Advanced with AI",
      enterprise: "Advanced with Custom AI"
    },
    {
      feature: "Support",
      starter: "Standard",
      professional: "Priority",
      enterprise: "24/7 Dedicated"
    },
    {
      feature: "Analytics",
      starter: "Basic",
      professional: "Advanced",
      enterprise: "Custom"
    },
    {
      feature: "API Access",
      starter: false,
      professional: false,
      enterprise: true
    },
    {
      feature: "Custom Branding",
      starter: false,
      professional: true,
      enterprise: true
    },
    {
      feature: "Multi-location Support",
      starter: false,
      professional: false,
      enterprise: true
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
          <h1 className="text-5xl font-bold text-blue-900 mb-4">Simple, Transparent Pricing</h1>
          <p className="text-xl text-blue-800/80 max-w-2xl mx-auto">
            Choose the plan that fits your clinic's needs.
          </p>
        </motion.div>
      </section>

      {/* Pricing Toggle */}
      <section className="py-8">
        <div className="container mx-auto px-6">
          <div className="flex items-center justify-center gap-4">
            <span className={`text-lg ${!isAnnual ? 'text-blue-900 font-semibold' : 'text-blue-800/70'}`}>
              Monthly
            </span>
            <button
              onClick={() => setIsAnnual(!isAnnual)}
              className={`w-16 h-8 rounded-full p-1 transition-colors ${
                isAnnual ? 'bg-blue-600' : 'bg-gray-300'
              }`}
            >
              <motion.div
                animate={{ x: isAnnual ? 32 : 0 }}
                className="w-6 h-6 bg-white rounded-full"
              />
            </button>
            <span className={`text-lg ${isAnnual ? 'text-blue-900 font-semibold' : 'text-blue-800/70'}`}>
              Annually
              <span className="ml-2 text-sm text-green-600 font-medium">Save 20%</span>
            </span>
          </div>
        </div>
      </section>

      {/* Pricing Cards */}
      <section className="py-12">
        <div className="container mx-auto px-6">
          <div className="grid md:grid-cols-3 gap-8">
            {plans.map((plan, index) => (
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
                    <span className="text-4xl font-bold text-blue-900">
                      ${plan.price}
                    </span>
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

      {/* Feature Comparison */}
      <section className="py-20 bg-gray-50">
        <div className="container mx-auto px-6">
          <h2 className="text-3xl font-bold text-blue-900 text-center mb-12">
            Compare Features
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b-2 border-blue-100">
                  <th className="py-4 px-6 text-left text-blue-900">Feature</th>
                  <th className="py-4 px-6 text-center text-blue-900">Starter</th>
                  <th className="py-4 px-6 text-center text-blue-900">Professional</th>
                  <th className="py-4 px-6 text-center text-blue-900">Enterprise</th>
                </tr>
              </thead>
              <tbody>
                {featureComparison.map((item, index) => (
                  <tr key={index} className="border-b border-blue-100">
                    <td className="py-4 px-6 text-blue-900">{item.feature}</td>
                    <td className="py-4 px-6 text-center">
                      {typeof item.starter === 'boolean' ? (
                        item.starter ? (
                          <Check className="w-5 h-5 text-green-600 mx-auto" />
                        ) : (
                          <X className="w-5 h-5 text-red-600 mx-auto" />
                        )
                      ) : (
                        <span className="text-blue-800/70">{item.starter}</span>
                      )}
                    </td>
                    <td className="py-4 px-6 text-center">
                      {typeof item.professional === 'boolean' ? (
                        item.professional ? (
                          <Check className="w-5 h-5 text-green-600 mx-auto" />
                        ) : (
                          <X className="w-5 h-5 text-red-600 mx-auto" />
                        )
                      ) : (
                        <span className="text-blue-800/70">{item.professional}</span>
                      )}
                    </td>
                    <td className="py-4 px-6 text-center">
                      {typeof item.enterprise === 'boolean' ? (
                        item.enterprise ? (
                          <Check className="w-5 h-5 text-green-600 mx-auto" />
                        ) : (
                          <X className="w-5 h-5 text-red-600 mx-auto" />
                        )
                      ) : (
                        <span className="text-blue-800/70">{item.enterprise}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-20">
        <div className="container mx-auto px-6">
          <h2 className="text-3xl font-bold text-blue-900 text-center mb-12">
            Frequently Asked Questions
          </h2>
          <div className="max-w-3xl mx-auto space-y-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="bg-white p-6 rounded-2xl shadow-lg"
            >
              <h3 className="text-xl font-semibold text-blue-900 mb-2">
                Can I upgrade or downgrade my plan?
              </h3>
              <p className="text-blue-800/70">
                Yes, you can change your plan at any time. Changes will be reflected in your next billing cycle.
              </p>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="bg-white p-6 rounded-2xl shadow-lg"
            >
              <h3 className="text-xl font-semibold text-blue-900 mb-2">
                Is there a setup fee?
              </h3>
              <p className="text-blue-800/70">
                No, there are no setup fees. You only pay the monthly or annual subscription fee.
              </p>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="bg-white p-6 rounded-2xl shadow-lg"
            >
              <h3 className="text-xl font-semibold text-blue-900 mb-2">
                Do you offer custom plans?
              </h3>
              <p className="text-blue-800/70">
                Yes, we offer custom enterprise solutions. Contact our sales team to discuss your specific needs.
              </p>
            </motion.div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Pricing;