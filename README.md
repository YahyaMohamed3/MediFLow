# MediFlow React Frontend and Flask API

This repository combines a Flask backend with a React frontend.

## Development

1. **Start the Flask API**

   ```bash
   FLASK_APP=src/app.py flask run
   ```

2. **Run the React dev server**

   ```bash
   cd frontend/project
   npm install
   npm run dev
   ```

   The Vite configuration proxies API requests beginning with `/api` to `http://localhost:5000`.

## Production Build

Generate the React build and serve it through Flask:

```bash
cd frontend/project
npm run build
```

The build output should be copied to `frontend/build`. Flask is configured to
serve files from this directory under the `/app` path.

## API Endpoints

The Flask backend exposes several JSON endpoints consumed by the React app:

- `POST /api/login` – authenticate a user
- `POST /api/register` – create a new admin account
- `GET /api/dashboard` – fetch dashboard metrics
- `GET /api/users` – list clinic users (admin only)
- `POST /api/users` – create a new user
- `GET /api/doctors` – list doctors (admin only)
- `POST /api/doctors` – create a new doctor
- `GET /api/patients` – list patients
- `POST /api/patients` – create a new patient (receptionist)
- `GET /api/appointments` – list appointments
- `POST /api/appointments` – create a new appointment (receptionist)
- `GET /api/analytics` – gender distribution statistics
- `GET /api/messages` – retrieve recent messages
- `POST /api/messages` – send a new message
- `GET /api/expenses` – list expense categories
- `GET /api/medical-records` – list medical records
- `POST /api/upload` – upload a document
- `POST /api/forgot` – request password reset email
- `POST /api/reset` – reset account password
- `GET /api/equipments` – list equipment purchases
- `GET /api/marketing` – list marketing expenses
- `GET /api/medical-supplies` – list medical supplies
- `GET /api/other-expenses` – list miscellaneous expenses
- `GET /api/utilities` – list utility bills
- `GET /api/billing` – list invoices and payment status
- `GET /api/prescriptions` – list prescriptions for the current doctor/admin
- `GET /api/doctor/dashboard` – upcoming appointments for the logged in doctor
- `GET /api/doctor/patients` – patients under the logged in doctor
- `GET/POST /api/doctor/prescriptions/<patient_id>` – manage prescriptions for a patient
- `GET /api/doctor/records/<patient_id>` – medical records for a patient
- `GET /api/receptionist` – today’s appointments for the receptionist
- `GET /api/schedule/<doctor_id>` – working hours for a doctor
- `GET /api/expenses/salaries` – salary expenses
- `GET /api/view_doctors` – list doctors for the admin
- `GET /api/patients/<id>/details` – full patient details
- `GET /api/patients/<id>/appointments` – patient appointment history

All endpoints require the Flask session for authentication.
