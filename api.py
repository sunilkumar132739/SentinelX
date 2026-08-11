from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
import nmap
import datetime
import requests
import os
from fpdf import FPDF
from fastapi.responses import FileResponse
from apscheduler.schedulers.background import BackgroundScheduler
from pydantic import BaseModel

# Database Setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./sentinelx.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String, index=True)
    hostname = Column(String)
    scan_time = Column(DateTime, default=datetime.datetime.utcnow)
    services = relationship("ServiceDetail", back_populates="scan")

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
    scan = relationship("ScanHistory", back_populates="services")

Base.metadata.create_all(bind=engine)

# Initialize FastAPI & Scheduler
app = FastAPI(title="SentinelX API", version="0.5")
scheduler = BackgroundScheduler()
scheduler.start()

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

def get_cves_for_service(service_name, version):
    if not version or len(version) < 2: return []
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service_name} {version}&resultsPerPage=3"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return [v.get("cve", {}).get("id") for v in response.json().get("vulnerabilities", []) if v.get("cve", {}).get("id")]
    except:
        pass
    return []

# CORE SCAN FUNCTION - Can be called by API or by Scheduler
def perform_scan(target: str):
    print(f"[*] Starting scan on target: {target}")
    db = SessionLocal() # Open DB session for background task
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-sV -F')
        host = target if target in nm.all_hosts() else (nm.all_hosts()[0] if nm.all_hosts() else None)
        if not host:
            print(f"[-] Scan failed: Target {target} down.")
            return None
        
        hostname = nm[host].hostname() if nm[host].hostname() else host
        previous_scan = db.query(ScanHistory).filter(ScanHistory.target_ip == host).order_by(ScanHistory.scan_time.desc()).first()
        previous_ports = [svc.port for svc in previous_scan.services if svc.state == 'open'] if previous_scan else []

        db_scan = ScanHistory(target_ip=host, hostname=hostname)
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        services_data = []
        current_open_ports = []

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                full_version = f"{nm[host][proto][port].get('product', '')} {nm[host][proto][port].get('version', '')}".strip()
                
                if state == 'open': current_open_ports.append(port)
                cves_str = ",".join(get_cves_for_service(name, nm[host][proto][port].get('version', ''))) if state == 'open' and full_version else ""

                svc = ServiceDetail(scan_id=db_scan.id, port=port, protocol=proto, state=state, service_name=name, version_info=full_version, cves=cves_str)
                db.add(svc)
                services_data.append({"port": port, "protocol": proto, "state": state, "service": name, "version_info": full_version, "cves": cves_str.split(",") if cves_str else []})
        
        db.commit()
        changes = {"is_first_scan": previous_scan is None, "new_ports": list(set(current_open_ports) - set(previous_ports)), "closed_ports": list(set(previous_ports) - set(current_open_ports))}
        print(f"[+] Scan completed for {target}")
        
        return {"scan_id": db_scan.id, "target_ip": host, "hostname": hostname, "scan_time": db_scan.scan_time.isoformat(), "services": services_data, "changes": changes}
    finally:
        db.close() # Always close DB session

# API Endpoints
@app.get("/")
def root(): return {"status": "SentinelX API is online"}

@app.get("/scan/{target}")
def api_scan_target(target: str):
    result = perform_scan(target)
    if not result: raise HTTPException(status_code=404, detail="Target not found or down")
    return result

# NEW PHASE 4: Schedule Endpoint
class ScheduleRequest(BaseModel):
    target: str
    minutes: int

@app.post("/schedule")
def schedule_scan(req: ScheduleRequest):
    job_id = f"scan_{req.target}_{req.minutes}m"
    # Schedule the perform_scan function to run every X minutes
    scheduler.add_job(perform_scan, 'interval', minutes=req.minutes, args=[req.target], id=job_id, replace_existing=True)
    return {"message": f"Successfully scheduled background scan for {req.target} every {req.minutes} minutes.", "job_id": job_id}

@app.get("/history")
def get_history(db: Session = Depends(get_db)):
    scans = db.query(ScanHistory).order_by(ScanHistory.scan_time.desc()).all()
    return [{"id": s.id, "target": s.target_ip, "time": s.scan_time.isoformat()} for s in scans]

@app.get("/history/{scan_id}")
def get_scan_result(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    return {"scan_id": scan.id, "target_ip": scan.target_ip, "hostname": scan.hostname, "scan_time": scan.scan_time.isoformat(), "services": [{"port": svc.port, "protocol": svc.protocol, "state": svc.state, "service": svc.service_name, "version_info": svc.version_info, "cves": svc.cves.split(",") if svc.cves else []} for svc in scan.services]}

@app.get("/scans/{scan_id}/pdf")
def download_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SentinelX Security Report", ln=True, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(200, 10, txt=f"Target: {scan.target_ip}", ln=True)
    pdf.ln(10)
    for svc in scan.services:
        pdf.cell(200, 10, txt=f"Port {svc.port} - {svc.state.upper()} ({svc.service_name})", ln=True)
    file_path = f"sentinelx_report_{scan_id}.pdf"
    pdf.output(file_path)
    return FileResponse(path=file_path, filename=file_path, media_type='application/pdf')