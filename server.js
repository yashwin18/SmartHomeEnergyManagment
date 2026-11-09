require("dotenv").config()

const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer")
const cors = require("cors")
const Database = require("better-sqlite3")
const http = require("http")
const { Server } = require("socket.io")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const crypto = require("crypto")

const app = express()

const server = http.createServer(app)
const io = new Server(server)



app.disable("x-powered-by")
app.use(helmet({ contentSecurityPolicy: false }))
app.use(express.json({ limit: "20kb" }))
app.use(cors({ origin: process.env.CLIENT_ORIGIN || false }))
app.use(express.static("public"))
app.use(["/login","/register","/send-otp","/verify-otp","/update-password","/setup/admin"], rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false }))
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters")

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
db.prepare("INSERT OR IGNORE INTO settings(id,electricity_rate,alert_threshold) VALUES(1,0.15,1.5)").run()

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

app.post("/send-otp",async(req,res)=>{
const email=String(req.body.email || "").trim().toLowerCase()
const purpose=req.body.purpose
if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !["signup","reset"].includes(purpose)) return res.status(400).json({message:"Valid email and OTP purpose required"})
if(purpose==="reset" && !db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(404).json({message:"Account not found"})
const otp=crypto.randomInt(100000,1000000).toString()
try {
  db.prepare("DELETE FROM otps WHERE email=? AND purpose=?").run(email,purpose)
  db.prepare("INSERT INTO otps(email,otp,purpose,expiry) VALUES(?,?,?,?)").run(email,otp,purpose,Date.now()+300000)
  await transporter.sendMail({from:process.env.EMAIL_USER,to:email,subject:"Smart Home verification code",text:"Your verification code is "+otp+". It expires in 5 minutes."})
  return res.json({message:"OTP sent"})
} catch(error) {
  db.prepare("DELETE FROM otps WHERE email=? AND purpose=?").run(email,purpose)
  console.error("OTP delivery failed:",error.message)
  return res.status(503).json({message:"Unable to send OTP. Check email configuration."})
}
})

/* ================= VERIFY OTP ================= */

app.post("/verify-otp",(req,res)=>{

const email=String(req.body.email || "").trim().toLowerCase()
const otp=String(req.body.otp || "")
const purpose=req.body.purpose
if(!["signup","reset"].includes(purpose)) return res.status(400).json({message:"Invalid OTP purpose"})
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

const {email,password,otp}=req.body
const role="homeowner"
const normalizedEmail=String(email || "").trim().toLowerCase()
if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || typeof password!=="string" || password.length<10 || password.length>128) return res.status(400).json({message:"Valid email and a 10-128 character password are required"})
const signupOtp=db.prepare("SELECT * FROM otps WHERE email=? AND purpose=?").get(normalizedEmail,"signup")
if(!signupOtp || signupOtp.expiry<Date.now() || signupOtp.otp!==String(otp || "")) return res.status(400).json({message:"Valid signup OTP required"})
db.prepare("DELETE FROM otps WHERE email=? AND purpose=?").run(normalizedEmail,"signup")

const exists=db.prepare("SELECT * FROM users WHERE email=?").get(normalizedEmail)

if(exists){
return res.status(400).json({message:"Email already registered"})
}

const hash=await bcrypt.hash(password,10)

db.prepare(
"INSERT INTO users(email,password,role) VALUES(?,?,?)"
).run(normalizedEmail,hash,role)

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

const emailNormalized=String(req.body.email || "").trim().toLowerCase()
const password=String(req.body.password || "")
const role=req.body.role
if(!emailNormalized || !password || !["admin","homeowner","technician"].includes(role)) return res.status(400).json({message:"Email, password and role are required"})
const user=db.prepare("SELECT * FROM users WHERE email=?").get(emailNormalized)

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

const email=String(req.body.email || "").trim().toLowerCase()
const password=String(req.body.password || "")
const otp=String(req.body.otp || "")
const record=db.prepare("SELECT * FROM otps WHERE email=? AND purpose=?").get(email,"reset")
if(!db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(404).json({message:"Account not found"})
if(!record || record.expiry<Date.now() || record.otp!==otp) return res.status(400).json({message:"Valid reset OTP required"})
if(password.length<10 || password.length>128) return res.status(400).json({message:"Password must be 10-128 characters"})
db.prepare("DELETE FROM otps WHERE email=? AND purpose=?").run(email,"reset")

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

/* ================= HOMEOWNER WRITE GUARDS ================= */
function requireHomeowner(req,res,next){
  if(req.user.role !== "homeowner") return res.status(403).json({message:"Homeowner access only"});
  next();
}
function verifyOwnedDevice(req,res,next){
  const id = req.body.device_id || req.params.id;
  const device = db.prepare("SELECT id FROM devices WHERE id=? AND owner=?").get(id,req.user.email);
  if(!device) return res.status(404).json({message:"Device not found"});
  next();
}
app.use("/homeowner/toggle-device",authenticate,requireHomeowner,verifyOwnedDevice);
app.use("/homeowner/update-device",authenticate,requireHomeowner,verifyOwnedDevice);
app.use("/homeowner/update-device-status",authenticate,requireHomeowner,verifyOwnedDevice);
app.use("/homeowner/delete-device",authenticate,requireHomeowner,verifyOwnedDevice);
app.use("/homeowner/add-device",authenticate,requireHomeowner);
app.use("/homeowner/monthly-energy",authenticate,requireHomeowner);

/* ================= FIRST ADMIN BOOTSTRAP ================= */
app.post("/setup/admin",async(req,res)=>{
const supplied=String(req.headers["x-setup-key"] || "")
const expected=String(process.env.BOOTSTRAP_ADMIN_KEY || "")
if(!expected || supplied.length!==expected.length || !crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(expected))) return res.status(403).json({message:"Invalid setup key"})
if(db.prepare("SELECT id FROM users WHERE role=?").get("admin")) return res.status(409).json({message:"An administrator already exists"})
const email=String(req.body.email || "").trim().toLowerCase()
const password=String(req.body.password || "")
if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<12 || password.length>128) return res.status(400).json({message:"Valid email and 12-128 character password required"})
if(db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(409).json({message:"Email already registered"})
const hash=await bcrypt.hash(password,12)
db.prepare("INSERT INTO users(email,password,role) VALUES(?,?,?)").run(email,hash,"admin")
db.prepare("INSERT INTO system_logs(message,created_at) VALUES(?,CURRENT_TIMESTAMP)").run("Initial administrator provisioned: "+email)
res.status(201).json({message:"Initial administrator created. Remove BOOTSTRAP_ADMIN_KEY from environment now."})
})
/* ================= ADMIN USERS ================= */

app.post("/admin/users",authenticate,requireAdmin,async(req,res)=>{
const email=String(req.body.email || "").trim().toLowerCase()
const password=String(req.body.password || "")
const role=req.body.role
if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<10 || password.length>128 || !["admin","technician","homeowner"].includes(role)) return res.status(400).json({message:"Valid email, 10-128 character password and supported role required"})
if(db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(409).json({message:"Email already registered"})
const hash=await bcrypt.hash(password,10)
db.prepare("INSERT INTO users(email,password,role) VALUES(?,?,?)").run(email,hash,role)
db.prepare("INSERT INTO system_logs(message,created_at) VALUES(?,CURRENT_TIMESTAMP)").run("User provisioned: "+email+" ("+role+") by "+req.user.email)
res.status(201).json({message:"User created"})
})
app.get("/admin/users",authenticate,requireAdmin,(req,res)=>{

const users=db.prepare("SELECT id,email,role FROM users").all()

res.json(users)

})

app.delete("/admin/delete-user/:id",authenticate,requireAdmin,(req,res)=>{

const id=req.params.id

const user=db.prepare("SELECT * FROM users WHERE id=?").get(id)
if(!user) return res.status(404).json({message:"User not found"})
if(user.id===req.user.id) return res.status(400).json({message:"You cannot delete your own account while signed in"})
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
if(!device) return res.status(404).json({message:"Device not found"})
db.prepare("DELETE FROM energy_logs WHERE device_id=?").run(id)
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
const rate=Number(req.body.electricity_rate)
const threshold=Number(req.body.alert_threshold)
if(!Number.isFinite(rate) || rate<0 || rate>100000 || !Number.isFinite(threshold) || threshold<=0 || threshold>1000000) return res.status(400).json({message:"Enter a valid non-negative electricity rate and positive alert threshold"})
db.prepare("UPDATE settings SET electricity_rate=?,alert_threshold=? WHERE id=1").run(rate,threshold)
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

app.post("/technician/update-device",authenticate,(req,res)=>{
if(req.user.role!=="technician") return res.status(403).json({message:"Technician access only"})
const {device_id,status}=req.body
if(!["Active","Offline"].includes(status)) return res.status(400).json({message:"Invalid status"})
const result=db.prepare("UPDATE devices SET status=? WHERE id=?").run(status,device_id)
if(!result.changes) return res.status(404).json({message:"Device not found"})
res.json({message:"Device status updated"})
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
if(req.user.role!=="technician") return res.status(403).json({message:"Technician access only"})
const {device_id,energy}=req.body
if(!Number.isFinite(Number(energy)) || Number(energy)<0) return res.status(400).json({message:"Energy must be a non-negative number"})
if(!db.prepare("SELECT id FROM devices WHERE id=?").get(device_id)) return res.status(404).json({message:"Device not found"})

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

const settings=db.prepare("SELECT electricity_rate FROM settings WHERE id=1").get()
res.json({total:total,today:today,electricity_rate:settings ? settings.electricity_rate : 0})

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
const name=String(req.body.name || "").trim()
const power=Number(req.body.power_rating)
if(!name || name.length>80 || !Number.isFinite(power) || power<=0 || power>100000) return res.status(400).json({message:"Provide a device name and a valid positive power rating"})
db.prepare("INSERT INTO devices(name,owner,power_rating,status) VALUES(?,?,?,?)").run(name,req.user.email,power,"Active")
res.status(201).json({message:"Device added"})
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
SELECT date(e.timestamp) as day,SUM(e.energy_used) as energy
FROM energy_logs e JOIN devices d ON d.id=e.device_id
WHERE d.owner=? GROUP BY date(e.timestamp) ORDER BY day
`).all(req.user.email)

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

io.use((socket,next)=>{
try { const token=socket.handshake.auth && socket.handshake.auth.token; socket.user=jwt.verify(token,process.env.JWT_SECRET); next() }
catch(error) { next(new Error("Unauthorized")) }
})
io.on("connection",(socket)=>{
socket.join("user:"+socket.user.email)

console.log("Client connected")

socket.on("disconnect",()=>{
console.log("Client disconnected")
})

})
setInterval(()=>{

const devices = db.prepare("SELECT * FROM devices WHERE status='Active'").all()

const settings = db.prepare("SELECT * FROM settings LIMIT 1").get()

devices.forEach(device=>{

const energy = (Math.max(0,Number(device.power_rating) || 0) * (5/3600) * (0.5 + Math.random())).toFixed(4)

/* store energy log */

db.prepare(`
INSERT INTO energy_logs(device_id,energy_used,timestamp)
VALUES(?,?,datetime('now'))
`).run(device.id,energy)

/* send live update */

io.to("user:"+device.owner).emit("energyUpdate",{
device:device.name,
energy:energy
})

/* check alert threshold */

if(settings && Number(energy) > settings.alert_threshold){

io.to("user:"+device.owner).emit("energyAlert",{
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
