# SentinelX 🛡️

**Automated Attack Surface Assessment & Vulnerability Management Platform**

SentinelX is a full-stack security tool designed to automate network reconnaissance, identify running services, and correlate discovered software versions with known vulnerabilities (CVEs) in real-time.

## Features

* **Active Reconnaissance:** Utilizes the Nmap engine to perform accurate service and version detection on target IPs/domains.
* **Threat Intelligence Integration:** Automatically queries the NIST National Vulnerability Database (NVD) API to map discovered services to known CVEs.
* **REST API Backend:** High-performance asynchronous backend built with Python and FastAPI.
* **Persistent Storage:** Stores target data, scan history, and vulnerability associations using SQLAlchemy and SQLite.
* **Interactive Dashboard:** A sleek, single-page React frontend tailored for security analysts to trigger scans, visualize risk, and download PDF reports.

## Tech Stack

* **Backend:** Python 3, FastAPI, SQLAlchemy, Uvicorn
* **Frontend:** React.js, Tailwind CSS, HTML5
* **Security Tools:** Nmap (`python-nmap`), NIST NVD API
* **Database:** SQLite

## Prerequisites

Before running SentinelX, ensure you have the following installed:
* [Python 3.8+](https://www.python.org/downloads/)
* [Nmap](https://nmap.org/download.html) (Must be added to your system PATH)

## Installation & Setup

1. **Clone the repository:**
   
```bash
   git clone [https://github.com/YOUR_USERNAME/SentinelX.git](https://github.com/YOUR_USERNAME/SentinelX.git)
   cd SentinelX