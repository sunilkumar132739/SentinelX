from fastapi.staticfiles import StaticFiles
from evidence import capture_web_evidence
import os
import asyncio
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
import jwt
import nmap
import datetime
import requests
from fpdf import FPDF
from fastapi.responses import FileResponse
from apscheduler.schedulers.background import BackgroundScheduler
from pydantic import BaseModel
from typing import Optional
import socket
import ssl
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Security Configuration ---
SECRET_KEY = "super_secret_sentinelx_key_change_in_production"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Database Setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./sentinelx.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True) 
    hashed_password = Column(String)
    avatar_data = Column(String, nullable=True)
    scans = relationship("ScanHistory", back_populates="owner")

class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id")) 
    target_ip = Column(String, index=True)
    hostname = Column(String)
    scan_type = Column(String, default="manual")
    scan_time = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    services = relationship("ServiceDetail", back_populates="scan", cascade="all, delete-orphan")
    owner = relationship("User", back_populates="scans")

class ServiceDetail(Base):
    __tablename__ = "service_details"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_history.id"))
    port = Column(Integer)
    protocol = Column(String)
    state = Column(String)
    service_name = Column(String)
    version_info = Column(String)
    cves = Column(String)
    web_info = Column(String, nullable=True)
    scan = relationship("ScanHistory", back_populates="services")

Base.metadata.create_all(bind=engine)

# --- Initialize FastAPI & Scheduler ---
app = FastAPI(title="SentinelX API", version="2.2")
scheduler = BackgroundScheduler()
scheduler.start()

# --- EVIDENCE STORE DIRECTORY MOUNT ---
if not os.path.exists("evidence_store"):
    os.makedirs("evidence_store")
app.mount("/evidence", StaticFiles(directory="evidence_store"), name="evidence")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth Helper Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# --- Auth & Profile Endpoints ---
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
def read_users_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    total_scans = db.query(ScanHistory).filter(ScanHistory.owner_id == current_user.id).count()
    return {
        "username": current_user.username,
        "email": current_user.email,
        "avatar_data": current_user.avatar_data,
        "total_scans": total_scans
    }

class AvatarUpdate(BaseModel):
    avatar_data: str

@app.put("/users/me/avatar")
def update_avatar(avatar: AvatarUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.avatar_data = avatar.avatar_data
    db.commit()
    return {"message": "Profile picture updated successfully"}

# --- Utility & Risk Engine Functions ---
def get_cves_for_service(service_name, version):
    if not version or len(version) < 2: return []
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service_name} {version}&resultsPerPage=3"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return [v.get("cve", {}).get("id") for v in response.json().get("vulnerabilities", []) if v.get("cve", {}).get("id")]
    except: pass
    return []

def analyze_web_target(ip, port):
    web_data = {}
    scheme = "https" if port in [443, 8443] else "http"
    url = f"{scheme}://{ip}:{port}"
    try:
        r = requests.get(url, timeout=3, verify=False)
        web_data["headers"] = {
            "Strict-Transport-Security": r.headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": r.headers.get("Content-Security-Policy", "Missing"),
            "X-Frame-Options": r.headers.get("X-Frame-Options", "Missing"),
            "Server": r.headers.get("Server", "Unknown")
        }
    except: pass

    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        web_data["tls"] = {
                            "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                            "expires": cert.get('notAfter', 'Unknown')
                        }
        except Exception as e:
            web_data["tls"] = {"error": "Invalid or inaccessible certificate"}
    return json.dumps(web_data) if web_data else None

def calculate_risk_metrics(services):
    score = 100
    remediations = []
    high_risk_ports = {
        21: ("FTP", "Disable unencrypted FTP and migrate to SFTP/SSH."),
        23: ("Telnet", "Disable Telnet immediately; plaintext authentication is exposed."),
        80: ("HTTP", "Enforce HTTPS redirect and install SSL/TLS certificate."),
        3389: ("RDP", "Restrict RDP access via VPN or IP whitelisting."),
        5900: ("VNC", "Secure VNC with strong authentication or SSH tunneling."),
        3306: ("MySQL", "Ensure MySQL is not exposed publicly to the internet."),
        5432: ("PostgreSQL", "Restrict PostgreSQL access to local/trusted IPs only."),
        27017: ("MongoDB", "Disable public MongoDB access and enable authentication.")
    }
    cve_count = 0
    for svc in services:
        if svc["state"] == "open":
            port = svc["port"]
            if port in high_risk_ports:
                score -= 15
                remediations.append(f"Port {port} ({high_risk_ports[port][0]}): {high_risk_ports[port][1]}")
            else:
                score -= 3

            cves = svc.get("cves", [])
            if cves:
                cve_count += len(cves)
                score -= (len(cves) * 10)
                remediations.append(f"Port {port} ({svc['service']}): Patch software version to resolve CVEs ({', '.join(cves)}).")

            web_info = svc.get("web_info")
            if web_info and isinstance(web_info, dict):
                headers = web_info.get("headers", {})
                missing_headers = [k for k, v in headers.items() if v == "Missing"]
                if missing_headers:
                    score -= (len(missing_headers) * 2)
                    remediations.append(f"Port {port} (Web): Missing security headers ({', '.join(missing_headers)}). Implement to prevent XSS/Clickjacking.")
                
                tls = web_info.get("tls", {})
                if tls and tls.get("error"):
                    score -= 10
                    remediations.append(f"Port {port} (TLS): Invalid or inaccessible SSL/TLS certificate detected.")

    score = max(0, min(100, score))
    risk_level = "LOW" if score >= 85 else "MEDIUM" if score >= 65 else "HIGH" if score >= 45 else "CRITICAL"

    return {
        "security_score": score,
        "risk_level": risk_level,
        "total_cves": cve_count,
        "remediations": remediations
    }

def perform_scan(target: str, owner_id: int, scan_type: str = "manual"):
    db = SessionLocal()
    nm = nmap.PortScanner()
    try:
        # 🚀 SPEED OPTIMIZATION 1: Added -T4 and --max-retries 1 for faster Nmap
        nm.scan(target, arguments='-sV -F -T4 --max-retries 1')
        host = target if target in nm.all_hosts() else (nm.all_hosts()[0] if nm.all_hosts() else None)
        if not host: return None
        hostname = nm[host].hostname() if nm[host].hostname() else host
        
        previous_scan = db.query(ScanHistory).filter(ScanHistory.target_ip == host, ScanHistory.owner_id == owner_id).order_by(ScanHistory.scan_time.desc()).first()
        previous_ports = [svc.port for svc in previous_scan.services if svc.state == 'open'] if previous_scan else []

        db_scan = ScanHistory(target_ip=host, hostname=hostname, scan_type=scan_type, owner_id=owner_id)
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        services_data = []
        current_open_ports = []
        web_targets = [] # Collect all web targets first

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                full_version = f"{nm[host][proto][port].get('product', '')} {nm[host][proto][port].get('version', '')}".strip()
                if state == 'open': current_open_ports.append(port)
                cves_str = ",".join(get_cves_for_service(name, nm[host][proto][port].get('version', ''))) if state == 'open' and full_version else ""

                if state == 'open' and (port in [80, 443, 8080, 8443] or 'http' in name):
                    web_targets.append({"port": port, "host": host})

                svc = ServiceDetail(
                    scan_id=db_scan.id, port=port, protocol=proto, state=state, service_name=name, 
                    version_info=full_version, cves=cves_str, web_info=None
                )
                db.add(svc)
                services_data.append({
                    "db_obj": svc, # Keep reference to update later
                    "port": port, "protocol": proto, "state": state, "service": name, "version_info": full_version, 
                    "cves": cves_str.split(",") if cves_str else [], "web_info": None
                })
        
        # 🚀 SPEED OPTIMIZATION 2: Run all screenshot tasks concurrently (Parallel)
        async def fetch_all_web_info():
            async def fetch_single(wt):
                p = wt["port"]
                h = wt["host"]
                web_info_str = analyze_web_target(h, p)
                web_info_dict = json.loads(web_info_str) if web_info_str else {}
                try:
                    screenshot_url = await capture_web_evidence(h, p)
                    if screenshot_url: web_info_dict["screenshot"] = screenshot_url
                except Exception: pass
                return p, web_info_dict
            
            tasks = [fetch_single(wt) for wt in web_targets]
            return await asyncio.gather(*tasks, return_exceptions=True)

        if web_targets:
            web_results = asyncio.run(fetch_all_web_info())
            web_map = {res[0]: res[1] for res in web_results if isinstance(res, tuple)}
            
            # Map fast results back to database
            for s in services_data:
                port = s["port"]
                if port in web_map:
                    s["web_info"] = web_map[port]
                    s["db_obj"].web_info = json.dumps(web_map[port])
        
        for s in services_data: del s["db_obj"] # Cleanup
        db.commit()

        changes = {"is_first_scan": previous_scan is None, "new_ports": list(set(current_open_ports) - set(previous_ports)), "closed_ports": list(set(previous_ports) - set(current_open_ports))}
        risk_metrics = calculate_risk_metrics(services_data)

        return {
            "scan_id": db_scan.id, "target_ip": host, "hostname": hostname, "scan_time": db_scan.scan_time.isoformat() + "Z",
            "services": services_data, "changes": changes, "risk_metrics": risk_metrics
        }
    finally:
        db.close()

# --- Protected API Endpoints ---

@app.get("/scan/{target}")
def api_scan_target(target: str, current_user: User = Depends(get_current_user)):
    result = perform_scan(target, owner_id=current_user.id, scan_type="manual")
    if not result: raise HTTPException(status_code=404, detail="Target down")
    return result

class ScheduleRequest(BaseModel):
    target: str
    schedule_type: str = "interval"
    minutes: Optional[int] = 60
    run_at: Optional[str] = None 

@app.post("/schedule")
def schedule_scan(req: ScheduleRequest, current_user: User = Depends(get_current_user)):
    if req.schedule_type == "datetime":
        if not req.run_at: raise HTTPException(status_code=400, detail="Specific date and time is required.")
        try: run_date_dt = datetime.datetime.fromisoformat(req.run_at)
        except ValueError: raise HTTPException(status_code=400, detail="Invalid date-time format.")
        
        job_id = f"scan_{req.target}_once_{req.run_at}_{current_user.id}"
        scheduler.add_job(perform_scan, 'date', run_date=run_date_dt, args=[req.target, current_user.id, "automated"], id=job_id, replace_existing=True)
        formatted_time = run_date_dt.strftime("%d %b %Y at %I:%M %p")
        return {"message": f"Successfully scheduled one-time scan for {req.target} on {formatted_time}", "job_id": job_id}
    else:
        job_id = f"scan_{req.target}_{req.minutes}m_{current_user.id}"
        scheduler.add_job(perform_scan, 'interval', minutes=req.minutes or 60, args=[req.target, current_user.id, "automated"], id=job_id, replace_existing=True)
        return {"message": f"Successfully scheduled recurring scan for {req.target} every {req.minutes} minutes.", "job_id": job_id}

@app.get("/schedules")
def get_schedules(current_user: User = Depends(get_current_user)):
    jobs = scheduler.get_jobs()
    user_jobs = []
    for job in jobs:
        if job.id.endswith(f"_{current_user.id}"):
            user_jobs.append({
                "id": job.id,
                "target": job.args[0], 
                "next_run": job.next_run_time.isoformat() if job.next_run_time else "Running now"
            })
    return user_jobs

@app.delete("/schedules/{job_id}")
def delete_schedule(job_id: str, current_user: User = Depends(get_current_user)):
    if not job_id.endswith(f"_{current_user.id}"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        scheduler.remove_job(job_id)
        return {"message": "Automated task terminated successfully."}
    except Exception:
        raise HTTPException(status_code=404, detail="Active task not found. It may have already completed.")

@app.get("/history")
def get_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = db.query(ScanHistory).filter(ScanHistory.owner_id == current_user.id).order_by(ScanHistory.scan_time.desc()).all()
    return [{"id": s.id, "target": s.target_ip, "time": s.scan_time.isoformat() + "Z", "scan_type": s.scan_type} for s in scans]

@app.get("/history/{scan_id}")
def get_scan_result(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.owner_id == current_user.id).first()
    if not scan: raise HTTPException(status_code=404, detail="Scan not found or unauthorized")
    
    services_data = []
    for svc in scan.services:
        web_info_dict = json.loads(svc.web_info) if svc.web_info else None
        services_data.append({
            "port": svc.port, "protocol": svc.protocol, "state": svc.state, "service": svc.service_name, 
            "version_info": svc.version_info, "cves": svc.cves.split(",") if svc.cves else [], "web_info": web_info_dict
        })
        
    risk_metrics = calculate_risk_metrics(services_data)

    return {
        "scan_id": scan.id, "target_ip": scan.target_ip, "hostname": scan.hostname,
        "scan_time": scan.scan_time.isoformat() + "Z", "scan_type": scan.scan_type,
        "services": services_data, "risk_metrics": risk_metrics
    }

@app.delete("/history")
def clear_all_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db.query(ScanHistory).filter(ScanHistory.owner_id == current_user.id).delete()
    db.commit()
    return {"message": "All your history cleared"}

@app.delete("/history/{scan_id}")
def delete_single_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.owner_id == current_user.id).first()
    if scan:
        db.delete(scan)
        db.commit()
    return {"message": "Scan deleted"}

@app.get("/scans/{scan_id}/pdf")
def download_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan: raise HTTPException(status_code=404, detail="Scan not found")
    
    services_data = [{"port": svc.port, "state": svc.state, "service": svc.service_name, "cves": svc.cves.split(",") if svc.cves else [], "web_info": json.loads(svc.web_info) if svc.web_info else None} for svc in scan.services]
    metrics = calculate_risk_metrics(services_data)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SentinelX Security Assessment Report", ln=True, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(200, 10, txt=f"Target: {scan.target_ip}", ln=True)
    pdf.cell(200, 10, txt=f"Security Score: {metrics['security_score']}/100 ({metrics['risk_level']} RISK)", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt="Discovered Services:", ln=True)
    pdf.set_font("Arial", '', 11)
    for svc in scan.services:
        pdf.cell(200, 8, txt=f" - Port {svc.port} ({svc.service_name}): {svc.state.upper()} | Version: {svc.version_info or 'N/A'}", ln=True)
        if svc.cves:
            pdf.cell(200, 6, txt=f"   CVEs: {svc.cves}", ln=True)

    if metrics["remediations"]:
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, txt="Remediation Recommendations:", ln=True)
        pdf.set_font("Arial", '', 10)
        for rem in metrics["remediations"]:
            pdf.multi_cell(0, 6, txt=f" * {rem}")

    file_path = f"sentinelx_report_{scan_id}.pdf"
    pdf.output(file_path)
    return FileResponse(path=file_path, filename=file_path, media_type='application/pdf')