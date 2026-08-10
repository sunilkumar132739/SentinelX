from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

# 1. Setup the SQLite database file
# This will create a file called 'sentinelx.db' in your project folder
SQLALCHEMY_DATABASE_URL = "sqlite:///./sentinelx.db"

# connect_args={"check_same_thread": False} is a specific requirement for SQLite in FastAPI
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# This creates a "factory" for database sessions (think of it as a connection window)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the parent class for all our database tables
Base = declarative_base()

# 2. Define the Database Tables (Models)
class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True)
    hostname = Column(String)
    
    # Link to the scans table (One target can have many scans)
    scans = relationship("ScanRun", back_populates="target")

class ScanRun(Base):
    __tablename__ = "scan_runs"
    
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    status = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Links
    target = relationship("Target", back_populates="scans")
    services = relationship("DiscoveredService", back_populates="scan")

class DiscoveredService(Base):
    __tablename__ = "discovered_services"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_runs.id"))
    
    port = Column(Integer)
    state = Column(String)
    service = Column(String)
    version_info = Column(String)
    cves = Column(String, default="") # NEW: Store CVEs as a comma-separated string
    
    # Link back to the scan run
    scan = relationship("ScanRun", back_populates="services")