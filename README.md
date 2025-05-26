🏥 Healthcare Analytics Dashboard
A web-based healthcare analytics dashboard built with Flask and SQLite, enabling role-based access and data-driven insights across hospitals.

🔑 Roles & Access
Superadmin: Full access to manage users, hospitals, and generate analytics

Hospital Admin: Manages departments and department admins within their hospital

Department Admin: Views and manages patient and admission data specific to their department

🔍 Key Features
OTP-verified user signup
Role-based data visibility and control
Dynamic visual analytics using X/Y-axis selectors and filters

Insights on:
Disease trends and department stats
Repeat admissions and recovery durations
Policy effectiveness and treatment delays
Blood sugar levels, allergies, age/gender distribution

🧩 Tech Stack
Backend: Flask + SQLAlchemy + SQLite
Frontend: HTML, CSS, JavaScript (Chart.js)

🗃️ Database
Core tables: users, hospitals, patients, admissions, data_entries, policy_inputs

Efficient joins based on selected filters to improve performance
