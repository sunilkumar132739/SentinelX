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
    cves = Column(String) # Store CVEs as comma-separated string
    scan = relationship("ScanHistory", back_populates="services")

Base.metadata.create_all(bind=engine)

# Initialize FastAPI
app = FastAPI(title="SentinelX API", version="0.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper: Fetch CVEs from NVD
def get_cves_for_service(service_name, version):
    if not version or len(version) < 2:
        return []
    
    search_query = f"{service_name} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_query}&resultsPerPage=3"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cve_list = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cve", {}).get("id")
                if cve_id:
                    cve_list.append(cve_id)
            return cve_list
    except Exception as e:
        print(f"NVD API Error: {e}")
    
    return []

@app.get("/")
def root():
    return {"status": "SentinelX API is online", "version": "0.4"}

@app.get("/scan/{target}")
def scan_target(target: str, db: Session = Depends(get_db)):
    nm = nmap.PortScanner()
    try:
        # Run Nmap scan
        nm.scan(target, arguments='-sV -F')
    except nmap.PortScannerError:
        raise HTTPException(status_code=500, detail="Nmap execution failed")
    
    if target not in nm.all_hosts():
        hosts = nm.all_hosts()
        if not hosts:
            raise HTTPException(status_code=404, detail="Target not found or down")
        host = hosts[0]
    else:
        host = target

    hostname = nm[host].hostname() if nm[host].hostname() else host
    
    # 1. NEW PHASE 3: Fetch Previous Scan for Diff Engine
    previous_scan = db.query(ScanHistory).filter(ScanHistory.target_ip == host).order_by(ScanHistory.scan_time.desc()).first()
    previous_ports = []
    if previous_scan:
        previous_ports = [svc.port for svc in previous_scan.services if svc.state == 'open']

    # 2. Save New Scan to Database
    db_scan = ScanHistory(target_ip=host, hostname=hostname)
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    services_data = []
    current_open_ports = []

    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            state = nm[host][proto][port]['state']
            name = nm[host][proto][port]['name']
            product = nm[host][proto][port].get('product', '')
            version = nm[host][proto][port].get('version', '')
            extrainfo = nm[host][proto][port].get('extrainfo', '')
            
            full_version = f"{product} {version} {extrainfo}".strip()
            
            if state == 'open':
                current_open_ports.append(port)
            
            # Fetch CVEs if port is open
            cve_list = []
            if state == 'open' and full_version:
                cve_list = get_cves_for_service(name, version)
            
            cves_str = ",".join(cve_list)

            svc = ServiceDetail(
                scan_id=db_scan.id,
                port=port,
                protocol=proto,
                state=state,
                service_name=name,
                version_info=full_version,
                cves=cves_str
            )
            db.add(svc)
            
            services_data.append({
                "port": port,
                "protocol": proto,
                "state": state,
                "service": name,
                "version_info": full_version,
                "cves": cve_list
            })
    
    db.commit()

    # 3. NEW PHASE 3: Calculate Differences
    changes = {
        "is_first_scan": previous_scan is None,
        "new_ports": [],
        "closed_ports": []
    }
    
    if previous_scan:
        changes["new_ports"] = list(set(current_open_ports) - set(previous_ports))
        changes["closed_ports"] = list(set(previous_ports) - set(current_open_ports))

    return {
        "scan_id": db_scan.id,
        "target_ip": host,
        "hostname": hostname,
        "scan_time": db_scan.scan_time.isoformat(),
        "services": services_data,
        "changes": changes
    }

@app.get("/history")
def get_history(db: Session = Depends(get_db)):
    scans = db.query(ScanHistory).order_by(ScanHistory.scan_time.desc()).all()
    return [{"id": s.id, "target": s.target_ip, "time": s.scan_time.isoformat()} for s in scans]

@app.get("/history/{scan_id}")
def get_scan_result(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    services_data = []
    for svc in scan.services:
        cve_list = svc.cves.split(",") if svc.cves else []
        services_data.append({
            "port": svc.port,
            "protocol": svc.protocol,
            "state": svc.state,
            "service": svc.service_name,
            "version_info": svc.version_info,
            "cves": cve_list
        })
    
    return {
        "scan_id": scan.id,
        "target_ip": scan.target_ip,
        "hostname": scan.hostname,
        "scan_time": scan.scan_time.isoformat(),
        "services": services_data
    }

@app.get("/scans/{scan_id}/pdf")
def download_pdf(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SentinelX Security Report", ln=True, align='C')
    
    pdf.set_font("Arial", '', 12)
    pdf.cell(200, 10, txt=f"Target: {scan.target_ip} ({scan.hostname})", ln=True)
    pdf.cell(200, 10, txt=f"Scan Date: {scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    
    pdf.ln(10)
    
    for svc in scan.services:
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt=f"Port {svc.port} ({svc.protocol}) - {svc.state.upper()}", ln=True)
        pdf.set_font("Arial", '', 12)
        pdf.cell(200, 10, txt=f"Service: {svc.service_name}", ln=True)
        if svc.version_info:
            pdf.cell(200, 10, txt=f"Version: {svc.version_info}", ln=True)
        if svc.cves:
            pdf.cell(200, 10, txt=f"CVEs: {svc.cves}", ln=True)
        pdf.ln(5)
        
    file_path = f"sentinelx_report_{scan_id}.pdf"
    pdf.output(file_path)
    
    return FileResponse(path=file_path, filename=file_path, media_type='application/pdf')