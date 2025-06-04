import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import About from './pages/About';
import Contact from './pages/Contact';
import Pricing from './pages/Pricing';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import AddUser from './pages/AddUser';
import Doctors from './pages/Doctors';
import AddDoctor from './pages/AddDoctor';
import Patients from './pages/Patients';
import AddPatient from './pages/AddPatient';
import Appointments from './pages/Appointments';
import AddAppointment from './pages/AddAppointment';
import Analytics from './pages/Analytics';
import Messages from './pages/Messages';
import Expenses from './pages/Expenses';
import Equipments from './pages/Equipments';
import Marketing from './pages/Marketing';
import MedicalSupplies from './pages/MedicalSupplies';
import OtherExpenses from './pages/OtherExpenses';
import Utilities from './pages/Utilities';
import Payments from './pages/Payments';
import Prescriptions from './pages/Prescriptions';
import MedicalRecords from './pages/MedicalRecords';
import Upload from './pages/Upload';
import Receptionist from './pages/Receptionist';
import Schedule from './pages/Schedule';
import Salaries from './pages/Salaries';
import ViewDoctors from './pages/ViewDoctors';
import ViewDetails from './pages/ViewDetails';
import PatientAppointments from './pages/PatientAppointments';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Success from './pages/Success';
import NotFound from './pages/NotFound';
import DoctorDashboard from './pages/DoctorDashboard';
import DoctorRecords from './pages/DoctorRecords';
import ManagePrescriptions from './pages/ManagePrescriptions';
import ManageRecords from './pages/ManageRecords';
import Layout from './pages/Layout';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/about" element={<About />} />
      <Route path="/contact" element={<Contact />} />
      <Route path="/pricing" element={<Pricing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/users" element={<Users />} />
        <Route path="/users/new" element={<AddUser />} />
        <Route path="/doctors" element={<Doctors />} />
        <Route path="/doctors/new" element={<AddDoctor />} />
        <Route path="/patients" element={<Patients />} />
        <Route path="/patients/new" element={<AddPatient />} />
        <Route path="/appointments" element={<Appointments />} />
        <Route path="/appointments/new" element={<AddAppointment />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/messages" element={<Messages />} />
        <Route path="/expenses" element={<Expenses />} />
        <Route path="/expenses/equipments" element={<Equipments />} />
        <Route path="/expenses/salaries" element={<Salaries />} />
        <Route path="/expenses/marketing" element={<Marketing />} />
        <Route path="/expenses/medical-supplies" element={<MedicalSupplies />} />
        <Route path="/expenses/other" element={<OtherExpenses />} />
        <Route path="/expenses/utilities" element={<Utilities />} />
        <Route path="/payments" element={<Payments />} />
        <Route path="/prescriptions" element={<Prescriptions />} />
        <Route path="/records" element={<MedicalRecords />} />
        <Route path="/patients/:patientId/appointments" element={<PatientAppointments />} />
        <Route path="/patients/:patientId/details" element={<ViewDetails />} />
        <Route path="/doctor" element={<DoctorDashboard />} />
        <Route path="/doctor/schedule/:doctorId" element={<Schedule />} />
        <Route path="/doctor/records" element={<DoctorRecords />} />
        <Route path="/doctor/prescriptions/:patientId" element={<ManagePrescriptions />} />
        <Route path="/records/:patientId" element={<ManageRecords />} />
        <Route path="/receptionist" element={<Receptionist />} />
        <Route path="/view-doctors" element={<ViewDoctors />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/forgot" element={<ForgotPassword />} />
        <Route path="/reset" element={<ResetPassword />} />
        <Route path="/success" element={<Success />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default App;
