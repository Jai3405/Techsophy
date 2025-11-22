"""
FastAPI web interface for Security Vulnerability Scanner.

Provides a user-friendly web UI for scanning repositories and viewing results.
"""

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
import uvicorn
from pathlib import Path
import shutil
import subprocess
import json
import os
from datetime import datetime
from typing import Optional, List
import uuid

app = FastAPI(
    title="DevOps Security Scanner",
    description="AI-Powered Vulnerability Detection System",
    version="1.0.0"
)

# Setup directories
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Setup templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# In-memory scan status tracking
scan_jobs = {}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with upload form."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


@app.post("/api/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    repo_path: str = Form(...),
    scan_types: str = Form("code,dependency,container,infrastructure"),
    severity_threshold: str = Form("LOW"),
    output_format: str = Form("both")
):
    """
    Start a new security scan.

    Args:
        repo_path: Path to repository to scan
        scan_types: Comma-separated scan types
        severity_threshold: Minimum severity level
        output_format: Output format (json, html, both)

    Returns:
        Scan job ID and status
    """
    # Validate repo path
    repo = Path(repo_path)
    if not repo.exists():
        raise HTTPException(status_code=400, detail=f"Repository path does not exist: {repo_path}")

    if not repo.is_dir():
        raise HTTPException(status_code=400, detail=f"Path is not a directory: {repo_path}")

    # Generate job ID
    job_id = str(uuid.uuid4())[:8]

    # Store job metadata
    scan_jobs[job_id] = {
        "id": job_id,
        "status": "queued",
        "repo_path": str(repo_path),
        "scan_types": scan_types,
        "severity_threshold": severity_threshold,
        "output_format": output_format,
        "created_at": datetime.now().isoformat(),
        "started_at": None,
        "completed_at": None,
        "error": None,
        "report_files": []
    }

    # Queue the scan as a background task
    background_tasks.add_task(run_scan, job_id)

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Scan started successfully"
    }


async def run_scan(job_id: str):
    """
    Execute the security scan.

    Args:
        job_id: Unique scan job identifier
    """
    job = scan_jobs[job_id]

    try:
        # Update status
        job["status"] = "running"
        job["started_at"] = datetime.now().isoformat()

        # Build command
        cmd = [
            "python", "-m", "src.main",
            "--repo-path", job["repo_path"],
            "--output-format", job["output_format"],
            "--severity-threshold", job["severity_threshold"]
        ]

        if job["scan_types"]:
            scan_types_list = job["scan_types"].split(",")
            cmd.extend(["--scan-types"] + scan_types_list)

        # Run scanner
        result = subprocess.run(
            cmd,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        # Find generated reports
        report_files = []
        if REPORTS_DIR.exists():
            # Get the most recent reports
            json_reports = sorted(REPORTS_DIR.glob("security_report_*.json"), key=os.path.getmtime, reverse=True)
            html_reports = sorted(REPORTS_DIR.glob("security_report_*.html"), key=os.path.getmtime, reverse=True)

            if json_reports:
                report_files.append(str(json_reports[0].name))
            if html_reports:
                report_files.append(str(html_reports[0].name))

        # Update job status
        job["status"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
        job["report_files"] = report_files
        job["stdout"] = result.stdout
        job["stderr"] = result.stderr
        job["exit_code"] = result.returncode

    except subprocess.TimeoutExpired:
        job["status"] = "failed"
        job["error"] = "Scan timed out after 5 minutes"
        job["completed_at"] = datetime.now().isoformat()
    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
        job["completed_at"] = datetime.now().isoformat()


@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    """
    Get scan job status.

    Args:
        job_id: Scan job identifier

    Returns:
        Job status and details
    """
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return scan_jobs[job_id]


@app.get("/api/scans")
async def list_scans():
    """List all scan jobs."""
    return {
        "total": len(scan_jobs),
        "scans": list(scan_jobs.values())
    }


@app.get("/api/reports")
async def list_reports():
    """List all available reports."""
    reports = []

    if REPORTS_DIR.exists():
        for report_file in sorted(REPORTS_DIR.iterdir(), key=os.path.getmtime, reverse=True):
            if report_file.suffix in ['.json', '.html']:
                reports.append({
                    "filename": report_file.name,
                    "type": report_file.suffix[1:],  # Remove leading dot
                    "size": report_file.stat().st_size,
                    "created_at": datetime.fromtimestamp(report_file.stat().st_mtime).isoformat()
                })

    return {"total": len(reports), "reports": reports}


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    """
    Download a specific report.

    Args:
        filename: Report filename

    Returns:
        Report file
    """
    report_path = REPORTS_DIR / filename

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    # Validate filename (security check)
    if not report_path.is_relative_to(REPORTS_DIR):
        raise HTTPException(status_code=400, detail="Invalid filename")

    return FileResponse(
        path=str(report_path),
        filename=filename,
        media_type="application/octet-stream"
    )


@app.get("/reports/{filename}", response_class=HTMLResponse)
async def view_html_report(filename: str):
    """
    View HTML report in browser.

    Args:
        filename: HTML report filename

    Returns:
        HTML report content
    """
    report_path = REPORTS_DIR / filename

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    if not filename.endswith('.html'):
        raise HTTPException(status_code=400, detail="Not an HTML report")

    # Validate filename (security check)
    if not report_path.is_relative_to(REPORTS_DIR):
        raise HTTPException(status_code=400, detail="Invalid filename")

    return FileResponse(path=str(report_path), media_type="text/html")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard showing all scans and reports."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.delete("/api/scan/{job_id}")
async def delete_scan(job_id: str):
    """Delete a scan job."""
    if job_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan job not found")

    del scan_jobs[job_id]
    return {"message": "Scan deleted successfully"}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔒 DevOps Security Scanner - Web Interface")
    print("="*60)
    print("\n🌐 Starting server at http://localhost:8000")
    print("📊 Dashboard: http://localhost:8000/dashboard")
    print("🔍 API Docs: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop\n")

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
