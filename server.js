require("dotenv").config()

const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer")
const cors = require("cors")
const Database = require("better-sqlite3")
const http = require("http")
const { Server } = require("socket.io")

const app = express()

const server = http.createServer(app)
const io = new Server(server)



app.use(express.json())
app.use(cors())
app.use(express.static("public"))

/* ================= DATABASE ================= */

const db = new Database("database.db")

db.prepare(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT UNIQUE,
password TEXT,
role TEXT
)
`).run()

db.prepare(`
CREATE TABLE IF NOT EXISTS otps(
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT,
otp TEXT,
purpose TEXT,
expiry INTEGER
)
`).run()

db.prepare(`
CREATE TABLE IF NOT EXISTS devices(
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
owner TEXT,
power_rating REAL,
status TEXT
)
`).run()

db.prepare(`
CREATE TABLE IF NOT EXISTS energy_logs(
id INTEGER PRIMARY KEY AUTOINCREMENT,
device_id INTEGER,
energy_used REAL,
timestamp TEXT
)
`).run()

db.prepare(`
CREATE TABLE IF NOT EXISTS system_logs(
id INTEGER PRIMARY KEY AUTOINCREMENT,
message TEXT,
created_at TEXT
)
`).run()

db.prepare(`
CREATE TABLE IF NOT EXISTS settings(
id INTEGER PRIMARY KEY AUTOINCREMENT,
electricity_rate REAL,
alert_threshold REAL
)
`).run()

console.log("SQLite connected")

/* ================= EMAIL ================= */

const transporter = nodemailer.createTransport({
service:"gmail",
auth:{
user:process.env.EMAIL_USER,
pass:process.env.EMAIL_PASS
}
})

/* ================= JWT ================= */

function generateToken(user){

return jwt.sign(
{ id:user.id,email:user.email,role:user.role },
process.env.JWT_SECRET,
{ expiresIn:"7d" }
)

}

/* ================= OTP ================= */

app.post("/send-otp", async (req, res) => {

const { email, purpose } = req.body

if (!email) {
return res.status(400).json({ message: "Email is required" })
}

const otp = Math.floor(100000 + Math.random() * 900000).toString()

try {

db.prepare("DELETE FROM otps WHERE email=? AND purpose=?")
.run(email, purpose)

db.prepare(
"INSERT INTO otps(email,otp,purpose,expiry) VALUES(?,?,?,?)"
).run(email, otp, purpose, Date.now() + 300000)

await transporter.sendMail({
from: process.env.EMAIL_USER,
to: email,
subject: "Smart Home OTP Verification",
text: `Your OTP is ${otp}`
})

res.json({ message: "OTP sent successfully" })

}catch(err){

console.error(err)
res.status(500).json({ message: "Failed to send OTP" })

}

})

/* ================= VERIFY OTP ================= */

app.post("/verify-otp",(req,res)=>{

const { email, otp, purpose } = req.body

const record=db.prepare(
"SELECT * FROM otps WHERE email=? AND purpose=?"
).get(email,purpose)

if(!record) return res.status(400).json({message:"OTP not found"})
if(record.expiry < Date.now()) return res.status(400).json({message:"OTP expired"})
if(record.otp !== otp) return res.status(400).json({message:"Invalid OTP"})

res.json({message:"OTP verified successfully"})

})

/* ================= REGISTER ================= */

app.post("/register",async(req,res)=>{

const {email,password,role}=req.body

const exists=db.prepare("SELECT * FROM users WHERE email=?").get(email)

if(exists){
return res.status(400).json({message:"Email already registered"})
}

const hash=await bcrypt.hash(password,10)

db.prepare(
"INSERT INTO users(email,password,role) VALUES(?,?,?)"
).run(email,hash,role)

/* SYSTEM LOG */

db.prepare(
"INSERT INTO system_logs(message,created_at) VALUES(?,datetime('now'))"
).run(`New User Registered
Email: ${email}
Role: ${role}`)

res.json({message:"Account created"})

})

/* ================= LOGIN ================= */

app.post("/login",async(req,res)=>{

const {email,password,role}=req.body

const user=db.prepare(
"SELECT * FROM users WHERE email=?"
).get(email)

if(!user) return res.status(400).json({message:"User not found"})
if(user.role!==role) return res.status(400).json({message:"Role mismatch"})

const valid=await bcrypt.compare(password,user.password)

if(!valid) return res.status(400).json({message:"Wrong password"})

const token=generateToken(user)

/* SYSTEM LOG */

db.prepare(
"INSERT INTO system_logs(message,created_at) VALUES(?,datetime('now'))"
).run(`User Login
Email: ${email}
Role: ${role}`)

res.json({token,role:user.role})

})

/* ================= RESET PASSWORD ================= */

app.post("/update-password",async(req,res)=>{

const {email,password}=req.body

const hash=await bcrypt.hash(password,10)

db.prepare(
"UPDATE users SET password=? WHERE email=?"
).run(hash,email)

res.json({message:"Password updated"})

})

/* ================= AUTH ================= */

function authenticate(req,res,next){

const auth=req.headers.authorization

if(!auth) return res.status(401).json({message:"Unauthorized"})

const token=auth.split(" ")[1]

try{

const user=jwt.verify(token,process.env.JWT_SECRET)

req.user=user
next()

}catch(err){

res.status(403).json({message:"Invalid Token"})

}

}

function requireAdmin(req,res,next){

if(req.user.role !== "admin"){
return res.status(403).json({message:"Admin access only"})
}

next()

}

/* ================= ADMIN USERS ================= */

app.get("/admin/users",authenticate,requireAdmin,(req,res)=>{

const users=db.prepare("SELECT id,email,role FROM users").all()

res.json(users)

})

app.delete("/admin/delete-user/:id",authenticate,requireAdmin,(req,res)=>{

const id=req.params.id

const user=db.prepare("SELECT * FROM users WHERE id=?").get(id)

db.prepare("DELETE FROM users WHERE id=?").run(id)

/* LOG */

db.prepare(
"INSERT INTO system_logs(message,created_at) VALUES(?,datetime('now'))"
).run(`User Deleted
Email: ${user.email}
Deleted by: ${req.user.email} (${req.user.role})`)

res.json({message:"User deleted"})

})

/* ================= ADMIN DEVICES ================= */

app.get("/admin/devices",authenticate,requireAdmin,(req,res)=>{

const devices=db.prepare("SELECT * FROM devices").all()

res.json(devices)

})

app.post("/admin/devices",authenticate,requireAdmin,(req,res)=>{

const {name,owner,power_rating,status}=req.body

db.prepare(
"INSERT INTO devices(name,owner,power_rating,status) VALUES(?,?,?,?)"
).run(name,owner,power_rating,status)

/* LOG */

db.prepare(
"INSERT INTO system_logs(message,created_at) VALUES(?,datetime('now'))"
).run(`Device Added
Device: ${name}
Owner: ${owner}
Power: ${power_rating} kW
Status: ${status}
Added by: ${req.user.email} (${req.user.role})`)

res.json({message:"Device added successfully"})

})

app.delete("/admin/device/:id",authenticate,requireAdmin,(req,res)=>{

const id=req.params.id

const device=db.prepare("SELECT * FROM devices WHERE id=?").get(id)

db.prepare("DELETE FROM devices WHERE id=?").run(id)

/* LOG */

db.prepare(
"INSERT INTO system_logs(message,created_at) VALUES(?,datetime('now'))"
).run(`Device Deleted
Device: ${device.name}
Owner: ${device.owner}
Deleted by: ${req.user.email} (${req.user.role})`)

res.json({message:"Device deleted"})

})

/* ================= ENERGY ================= */

app.get("/admin/energy",authenticate,requireAdmin,(req,res)=>{

const total=db.prepare(
"SELECT SUM(energy_used) as total FROM energy_logs"
).get()

const today=db.prepare(
"SELECT SUM(energy_used) as today FROM energy_logs WHERE date(timestamp)=date('now')"
).get()

res.json({
total:total.total || 0,
today:today.today || 0
})

})

/* ================= LOGS ================= */

app.get("/admin/logs",authenticate,requireAdmin,(req,res)=>{

const logs=db.prepare(
"SELECT * FROM system_logs ORDER BY id DESC"
).all()

res.json(logs)

})

/* ================= SETTINGS ================= */

app.get("/admin/settings",authenticate,requireAdmin,(req,res)=>{

const settings=db.prepare(
"SELECT * FROM settings LIMIT 1"
).get()

res.json(settings)

})

app.post("/admin/settings",authenticate,requireAdmin,(req,res)=>{

const {electricity_rate,alert_threshold}=req.body

db.prepare(`
UPDATE settings
SET electricity_rate=?,alert_threshold=?
WHERE id=1
`).run(electricity_rate,alert_threshold)

res.json({message:"Settings updated"})

})

/* ================= PROFILE ================= */

app.get("/profile",authenticate,(req,res)=>{

res.json({user:req.user})

})

/* ================= LANDING ================= */

app.get("/",(req,res)=>{
res.sendFile(__dirname+"/public/index.html")
})

/* ================= TECHNICIAN DEVICES ================= */

app.get("/technician/devices", authenticate, (req,res)=>{

if(req.user.role !== "technician"){
return res.status(403).json({message:"Technician access only"})
}

const devices = db.prepare(
"SELECT * FROM devices"
).all()

res.json(devices)

})

/* ================= ADD ENERGY LOG ================= */

app.post("/technician/energy", authenticate, (req,res)=>{

if(req.user.role !== "technician"){
return res.status(403).json({message:"Technician access only"})
}

const {device_id,energy_used}=req.body

db.prepare(
"INSERT INTO energy_logs(device_id,energy_used,timestamp) VALUES(?,?,datetime('now'))"
).run(device_id,energy_used)

/* system log */

db.prepare(
"INSERT INTO system_logs(message,created_at) VALUES(?,datetime('now'))"
).run(`Energy Recorded
Device ID: ${device_id}
Energy Used: ${energy_used} kWh
Recorded by: ${req.user.email} (Technician)`)

res.json({message:"Energy recorded"})

})

/* ================= TECHNICIAN LOGS-energy ================= */
app.post("/technician/log-energy", authenticate,(req,res)=>{

const {device_id,energy}=req.body

db.prepare(`
INSERT INTO energy_logs(device_id,energy_used,timestamp)
VALUES(?,?,datetime('now'))
`).run(device_id,energy)

db.prepare(`
INSERT INTO system_logs(message,created_at)
VALUES(?,datetime('now'))
`).run(`Energy logged for device ${device_id} by ${req.user.email}`)

res.json({message:"Energy recorded"})

})
/* ================= HOMEOWNER DEVICES ================= */

app.get("/homeowner/devices", authenticate, (req,res)=>{

if(req.user.role !== "homeowner"){
return res.status(403).json({message:"Homeowner access only"})
}

const devices=db.prepare(
"SELECT * FROM devices WHERE owner=?"
).all(req.user.email)

res.json(devices)

})

/* ================= HOMEOWNER ENERGY ================= */

app.get("/homeowner/energy", authenticate, (req,res)=>{

if(req.user.role !== "homeowner"){
return res.status(403).json({message:"Homeowner access only"})
}

const devices=db.prepare(
"SELECT id FROM devices WHERE owner=?"
).all(req.user.email)

let total=0
let today=0

devices.forEach(d=>{

const t=db.prepare(
"SELECT SUM(energy_used) as e FROM energy_logs WHERE device_id=?"
).get(d.id)

const td=db.prepare(
"SELECT SUM(energy_used) as e FROM energy_logs WHERE device_id=? AND date(timestamp)=date('now')"
).get(d.id)

total += t.e || 0
today += td.e || 0

})

res.json({
total:total,
today:today
})

})


/* ================= toggle-device ================= */

app.post("/homeowner/toggle-device", authenticate, (req,res)=>{

const {device_id,status}=req.body

db.prepare(
"UPDATE devices SET status=? WHERE id=?"
).run(status,device_id)

res.json({message:"Device updated"})

})
/* ================= add-device ================= */

app.post("/homeowner/add-device", authenticate, (req,res)=>{

const {name,power_rating}=req.body

db.prepare(
"INSERT INTO devices(name,owner,power_rating,status) VALUES(?,?,?,?)"
).run(name,req.user.email,power_rating,"Active")

res.json({message:"Device added"})

})

/* ================= update-device ================= */

app.post("/homeowner/update-device", authenticate, (req,res)=>{
const {device_id,name,power_rating}=req.body

db.prepare(
"UPDATE devices SET name=?,power_rating=? WHERE id=?"
).run(name,power_rating,device_id)
res.json({message:"Device updated"})
})

/* ================= update-device-status ================= */

app.post("/homeowner/update-device-status", authenticate, (req,res)=>{
const {device_id,status}=req.body
db.prepare(
"UPDATE devices SET status=? WHERE id=?"
).run(status,device_id)
res.json({message:"Device status updated"})

})

/* ================= monthly-energy ================= */
app.get("/homeowner/monthly-energy", authenticate,(req,res)=>{

const data=db.prepare(`
SELECT date(timestamp) as day,
SUM(energy_used) as energy
FROM energy_logs
GROUP BY day
ORDER BY day
`).all()

res.json(data)

})
/* ================= delete-device ================= */
app.delete("/homeowner/delete-device", authenticate, (req,res)=>{

const {device_id}=req.body

db.prepare(
"DELETE FROM devices WHERE id=?"
).run(device_id)

res.json({message:"Device deleted"})

})

io.on("connection",(socket)=>{

console.log("Client connected")

socket.on("disconnect",()=>{
console.log("Client disconnected")
})

})
setInterval(()=>{

const devices = db.prepare("SELECT * FROM devices").all()

const settings = db.prepare("SELECT * FROM settings LIMIT 1").get()

devices.forEach(device=>{

const energy = (Math.random()*2).toFixed(2)

/* store energy log */

db.prepare(`
INSERT INTO energy_logs(device_id,energy_used,timestamp)
VALUES(?,?,datetime('now'))
`).run(device.id,energy)

/* send live update */

io.emit("energyUpdate",{
device:device.name,
energy:energy
})

/* check alert threshold */

if(settings && Number(energy) > settings.alert_threshold){

io.emit("energyAlert",{
message:`⚠ High energy usage detected on ${device.name}`
})

}

})

},5000)
/* ================= SERVER ================= */

const PORT=process.env.PORT || 5000

server.listen(PORT,()=>{

console.log("🚀 Server running successfully!")
console.log("👉 Open in browser: http://localhost:"+PORT)

})
