from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware # NEW: Import the CORS tool
import nmap
import socket
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base, Target, ScanRun, DiscoveredService

# Create the database tables automatically when the app starts
Base.metadata.create_all(bind=engine)

# 1. Initialize the FastAPI application
app = FastAPI(
    title="SentinelX API",
    description="Backend engine for the SentinelX Attack Surface platform",
    version="0.3"
)

# --- NEW: Configure CORS to allow the frontend to talk to the backend ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (good for local testing)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)
# ------------------------------------------------------------------------

# 2. Define our Pydantic Data Models
# FastAPI uses these to automatically validate data coming in and going out,
# and generates free documentation for us!
from pydantic import BaseModel
from typing import List, Optional

# --- NEW: Import requests and time for NVD API ---
import requests
import time
# -------------------------------------------------

# --- NEW: Import PDF library ---
from fpdf import FPDF
from fastapi.responses import StreamingResponse
import io
# -------------------------------

# --- NEW: Database Helper Function ---
# This opens a connection to the database and ensures it closes when done
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# -------------------------------------

class ServiceInfo(BaseModel):
    port: int
    state: str
    service: str
    version_info: str
    cves: str = "" # NEW: Add CVEs to our Data Model

class ScanResult(BaseModel):
    target_ip: str
    hostname: str
    status: str
    services: List[ServiceInfo]

# --- NEW MODELS FOR HISTORY ---
from datetime import datetime

class ScanHistoryItem(BaseModel):
    id: int
    target_ip: str
    hostname: str
    status: str
    timestamp: datetime

# --- NEW: NVD API Helper Function ---
def fetch_cves_from_nvd(version_info: str) -> str:
    """Queries the NIST National Vulnerability Database for known CVEs."""
    if not version_info or version_info == "No version detected":
        return ""
    
    # Nmap gives us detailed banners like "OpenSSH 6.6.1p1 Ubuntu". 
    # If we search that entire string, NIST will get confused. 
    # We will just take the first two words (e.g., "OpenSSH 6.6") for a broader search.
    search_terms = " ".join(version_info.split()[:2])
    
    # We ask the API for a maximum of 3 results to keep things fast and clean
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_terms}&resultsPerPage=3"
    
    try:
        # NIST strictly rate-limits free, unauthenticated API calls (5 per 30 seconds).
        # We add a 1.5 second pause so they don't block our IP address.
        time.sleep(1.5) 
        
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cve_items = data.get("vulnerabilities", [])
            
            # Extract just the CVE IDs (like "CVE-2014-0001")
            cve_list = []
            for item in cve_items:
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    cve_list.append(cve_id)
                    
            return ", ".join(cve_list)
        elif response.status_code == 403:
            return "NVD API Rate Limited"
    except Exception as e:
        print(f"NVD API Error: {e}")
        
    return ""
# ------------------------------------

def run_nmap_scan(target: str) -> ScanResult:
    nm = nmap.PortScanner()
    
    try:
        # We are keeping the scan scope small (-p 22,80,443,3389) for speed during testing
        nm.scan(target, arguments='-p 22,80,443,3389 -sV')
    except nmap.PortScannerError as e:
        raise HTTPException(status_code=500, detail=f"Nmap Error: {e}")
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

    # If Nmap didn't find the host, return a 404
    if not nm.all_hosts():
        raise HTTPException(status_code=404, detail="Host not found or is down.")

    # 4. Parse the results into our new Data Models
    # We only take the first host since we are scanning one IP at a time
    host = nm.all_hosts()[0]
    hostname = nm[host].hostname()
    status = nm[host].state()
    
    discovered_services = []
    
    for proto in nm[host].all_protocols():
        ports = sorted(nm[host][proto].keys())
        
        for port in ports:
            port_data = nm[host][proto][port]
            
            # Extract info just like V0.2
            product = port_data.get('product', '')
            version = port_data.get('version', '')
            service_info = f"{product} {version}".strip()
            if not service_info:
                service_info = "No version detected"
            
            # --- NEW: Fetch CVEs dynamically ---
            cves_found = fetch_cves_from_nvd(service_info)
            # -----------------------------------
                
            # Create a ServiceInfo object and add it to our list
            svc = ServiceInfo(
                port=port,
                state=port_data.get('state', 'unknown'),
                service=port_data.get('name', 'unknown'),
                version_info=service_info,
                cves=cves_found # NEW: Attach the CVEs
            )
            discovered_services.append(svc)
            
    # Combine everything into the final ScanResult object
    return ScanResult(
        target_ip=host,
        hostname=hostname,
        status=status,
        services=discovered_services
    )

# 5. Define the API Routes (Endpoints)
@app.get("/")
def read_root():
    """Health check endpoint to see if the API is running."""
    return {"status": "SentinelX API is online", "version": "0.3"}

@app.get("/scan/{target}", response_model=ScanResult)
def scan_target(target: str, db: Session = Depends(get_db)):
    """
    Endpoint to trigger a scan.
    Example: http://localhost:8000/scan/scanme.nmap.org
    """
    # Quick safety check: ensure the target resolves to an IP before scanning
    try:
         socket.gethostbyname(target)
    except socket.gaierror:
         raise HTTPException(status_code=400, detail="Invalid hostname or IP address.")
         
    # Run the engine and get the JSON
    scan_data = run_nmap_scan(target)
    
    # --- NEW: Save to Database ---
    # 1. Find or create the target
    db_target = db.query(Target).filter(Target.ip == scan_data.target_ip).first()
    if not db_target:
        db_target = Target(ip=scan_data.target_ip, hostname=scan_data.hostname)
        db.add(db_target)
        db.commit()
        db.refresh(db_target)
        
    # 2. Create a new scan record
    db_scan = ScanRun(target_id=db_target.id, status=scan_data.status)
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # 3. Save all discovered services attached to this scan
    for svc in scan_data.services:
        db_svc = DiscoveredService(
            scan_id=db_scan.id,
            port=svc.port,
            state=svc.state,
            service=svc.service,
            version_info=svc.version_info,
            cves=svc.cves # NEW: Save CVEs to database
        )
        db.add(db_svc)
    
    db.commit()
    # -----------------------------

    return scan_data

# --- NEW: History Endpoints ---
@app.get("/scans", response_model=List[ScanHistoryItem])
def get_scan_history(db: Session = Depends(get_db)):
    """Fetch all previous scans."""
    scans = db.query(ScanRun, Target).join(Target).order_by(ScanRun.timestamp.desc()).all()
    
    history = []
    for scan, target in scans:
        history.append(ScanHistoryItem(
            id=scan.id,
            target_ip=target.ip,
            hostname=target.hostname,
            status=scan.status,
            timestamp=scan.timestamp
        ))
    return history

@app.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """Fetch the exact results of a specific older scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Reconstruct the services list
    services = []
    for svc in scan.services:
        services.append(ServiceInfo(
            port=svc.port,
            state=svc.state,
            service=svc.service,
            version_info=svc.version_info,
            cves=svc.cves or "" # NEW: Retrieve CVEs from database
        ))
        
    return ScanResult(
        target_ip=scan.target.ip,
        hostname=scan.target.hostname,
        status=scan.status,
        services=services
    )

# --- NEW: PDF Report Endpoint ---
@app.get("/scans/{scan_id}/pdf")
def download_scan_pdf(scan_id: int, db: Session = Depends(get_db)):
    """Generate and download a PDF report for a scan."""
    # 1. Fetch data from DB
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # 2. Initialize PDF
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("helvetica", "B", 24)
    pdf.set_text_color(41, 128, 185) # Blue color
    pdf.cell(0, 10, "SentinelX Security Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)
    
    # Target Info
    pdf.set_font("helvetica", "B", 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"Target: {scan.target.ip} ({scan.target.hostname or 'Unknown'})", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 10, f"Scan Date: {scan.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Status: {scan.status}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # Services Table Header
    pdf.set_font("helvetica", "B", 12)
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(30, 10, "Port", border=1, fill=True)
    pdf.cell(30, 10, "State", border=1, fill=True)
    pdf.cell(40, 10, "Service", border=1, fill=True)
    pdf.cell(90, 10, "Version Info", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    
    # Services Table Data
    pdf.set_font("helvetica", "", 10)
    for svc in scan.services:
        # Check if port is open to color it red
        if svc.state.lower() == 'open':
            pdf.set_text_color(200, 0, 0)
        else:
            pdf.set_text_color(0, 0, 0)
            
        pdf.cell(30, 10, str(svc.port), border=1)
        pdf.cell(30, 10, svc.state, border=1)
        pdf.set_text_color(0, 0, 0) # Reset color for remaining columns
        pdf.cell(40, 10, svc.service, border=1)
        
        # Handle long version info text
        version_text = svc.version_info
        if len(version_text) > 40:
             version_text = version_text[:37] + "..."
        pdf.cell(90, 10, version_text, border=1, new_x="LMARGIN", new_y="NEXT")
        
    # 3. Create response
    pdf_bytes = pdf.output()
    
    # Return as a downloadable file
    return StreamingResponse(
        io.BytesIO(pdf_bytes), 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=sentinelx_report_{scan.target.ip}.pdf"}
    )

# To run this server, use the command:
# uvicorn api:app --reload