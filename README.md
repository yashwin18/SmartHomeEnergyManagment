# 🏠 Smart Home Energy Management System

A full-stack **Smart Home Energy Management Platform** that allows homeowners, technicians, and administrators to monitor and manage energy consumption of smart devices in real time.

The system provides secure authentication with **Email OTP verification**, **Role-Based Access Control**, **Device Management**, **Energy Monitoring**, and **Live Alerts**.

---

# 🚀 Features

### 🔐 Authentication & Security
- Email OTP verification
- JWT based authentication
- Secure password hashing with bcrypt
- Role-based access (Admin, Technician, Homeowner)

### 👤 User Roles

#### 👨‍💼 Admin
- Manage users
- Manage devices
- Monitor total energy usage
- View system logs
- Configure electricity rates and alert thresholds

#### 🛠 Technician
- View all smart devices
- Log energy usage
- Monitor device diagnostics
- Update energy logs

#### 🏠 Homeowner
- Manage personal devices
- Toggle device status
- Monitor real-time energy consumption
- View daily & total energy usage
- Track monthly energy analytics

---

# ⚡ Real-Time Energy Monitoring

The system simulates smart device energy consumption and provides:

- Live energy updates using **Socket.IO**
- Automatic energy logging
- Real-time alerts when usage exceeds threshold

---

# 🧠 Smart System Capabilities

- Device-level energy monitoring
- Automated energy alerts
- Energy usage analytics
- Smart device management
- Real-time updates via WebSockets

---

# 🛠 Tech Stack

### Backend
- Node.js
- Express.js
- SQLite (better-sqlite3)
- JWT Authentication
- Nodemailer (Email OTP)
- Socket.IO (Real-time updates)

### Security
- bcryptjs
- JSON Web Tokens

### Frontend
- HTML
- CSS
- JavaScript
- Chart.js

---

# 📂 Project Structure


smart-home-energy-system
│
├── server.js
├── database.db
├── .env
│
├── public
│ ├── index.html
│ ├── home.html
│ ├── technician.html
│ ├── admin.html
│ │
│ ├── devices.html
│ ├── analytics.html
│ ├── scheduler.html
│ ├── recommendations.html
│ │
│ ├── homes.html
│ ├── diagnostics.html
│ ├── maintenance.html
│ │
│ ├── users.html
│ ├── roles.html
│ └── analytics.html


---

# 🔧 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/smart-home-energy-system.git
cd smart-home-energy-system
2️⃣ Install Dependencies
npm install
3️⃣ Create .env File
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password
JWT_SECRET=your_secret_key
PORT=5000
4️⃣ Start the Server
node server.js

Server will run at:

http://localhost:5000
🔑 API Endpoints
Authentication
Method	Endpoint	Description
POST	/send-otp	Send OTP to email
POST	/verify-otp	Verify OTP
POST	/register	Register user
POST	/login	Login user
Admin APIs
Endpoint	Description
GET /admin/users	Get all users
DELETE /admin/delete-user/:id	Delete user
GET /admin/devices	View all devices
POST /admin/devices	Add device
DELETE /admin/device/:id	Delete device
GET /admin/energy	Energy analytics
GET /admin/logs	System logs
Technician APIs
Endpoint	Description
GET /technician/devices	View devices
POST /technician/energy	Log energy usage
Homeowner APIs
Endpoint	Description
GET /homeowner/devices	Get personal devices
POST /homeowner/add-device	Add new device
POST /homeowner/toggle-device	Toggle device status
GET /homeowner/energy	View energy usage
GET /homeowner/monthly-energy	Monthly analytics
DELETE /homeowner/delete-device	Remove device
📊 Real-Time Updates

The system uses Socket.IO to stream live energy updates.

Example event:

energyUpdate

Example alert:

energyAlert
🔔 Energy Alerts

When a device consumes energy above the configured threshold:

⚠ High energy usage detected

An alert is emitted to connected clients.

📈 Energy Simulation

Every 5 seconds, the system:

Simulates device energy consumption

Stores energy logs

Sends live updates

Triggers alerts if threshold exceeded

🧪 Testing Roles

You can register with different roles:

admin
technician
homeowner

Each role gets different dashboard access.

🔒 Security Features

Password hashing

JWT protected APIs

Role-based access control

OTP email verification

🎯 Future Improvements

IoT device integration

AI-based energy optimization

Mobile app support

Smart automation scheduling

Energy prediction analytics

👨‍💻 Author

Developed by YASHWIN GOWDA K

Engineering Student | Smart Systems Developer

⭐ Support

If you like this project:

⭐ Star the repository
🍴 Fork it
📢 Share i
