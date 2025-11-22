# Web Interface Guide

## 🌐 FastAPI Web Interface

The security scanner now includes a **professional web interface** built with FastAPI, providing a complete product experience with beautiful UI and real-time scan monitoring.

---

## 🚀 Quick Start

### 1. Start the Web Server

```bash
python app.py
```

The server will start at **http://localhost:8000**

### 2. Access the Interface

- **Home Page**: http://localhost:8000
- **Dashboard**: http://localhost:8000/dashboard
- **API Documentation**: http://localhost:8000/docs

---

## ✨ Features

### 🎨 Home Page (Scan Launcher)
- Beautiful gradient UI with form-based scanning
- Configure scan parameters:
  - Repository path
  - Scan types (code, dependency, container, infrastructure)
  - Severity threshold
  - Report format (JSON, HTML, or both)
- Real-time scan status updates
- Direct links to generated reports

### 📊 Dashboard
- **Statistics Overview**:
  - Total scans
  - Completed scans
  - Running scans
  - Total reports
- **Recent Scans Table**:
  - Job ID tracking
  - Repository path
  - Status badges (queued, running, completed, failed)
  - Timestamp
  - Quick actions (view reports, delete scan)
- **Available Reports Table**:
  - Report filename
  - Type (JSON/HTML)
  - File size
  - Creation timestamp
  - View/download buttons
- **Auto-refresh**: Automatically updates every 5 seconds when scans are running

### 🔌 REST API Endpoints

#### Scan Management
- `POST /api/scan` - Start a new scan
- `GET /api/scan/{job_id}` - Get scan status
- `GET /api/scans` - List all scans
- `DELETE /api/scan/{job_id}` - Delete a scan

#### Reports
- `GET /api/reports` - List all reports
- `GET /api/reports/{filename}` - Download a report
- `GET /reports/{filename}` - View HTML report in browser

#### System
- `GET /api/health` - Health check
- `GET /docs` - Interactive API documentation (Swagger UI)

---

## 📖 Usage Examples

### Example 1: Scan via Web UI

1. Open http://localhost:8000
2. Enter repository path: `test_repo`
3. Select scan types: All (default)
4. Set severity: Low (default)
5. Choose format: JSON + HTML
6. Click "🚀 Start Security Scan"
7. Wait for completion (progress shown)
8. Click on report link to view results

### Example 2: Scan via API (curl)

```bash
# Start a scan
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "repo_path=test_repo&scan_types=code,container&severity_threshold=HIGH&output_format=both"

# Response:
# {
#   "job_id": "a3b2c1d4",
#   "status": "queued",
#   "message": "Scan started successfully"
# }

# Check scan status
curl "http://localhost:8000/api/scan/a3b2c1d4"

# List all scans
curl "http://localhost:8000/api/scans"

# Download JSON report
curl "http://localhost:8000/api/reports/security_report_20251123_120000.json" -o report.json
```

### Example 3: Scan via API (Python)

```python
import requests
import time

# Start scan
response = requests.post(
    "http://localhost:8000/api/scan",
    data={
        "repo_path": "test_repo",
        "scan_types": "code,dependency,container,infrastructure",
        "severity_threshold": "LOW",
        "output_format": "both"
    }
)

job_id = response.json()["job_id"]
print(f"Scan started: {job_id}")

# Poll for completion
while True:
    status_response = requests.get(f"http://localhost:8000/api/scan/{job_id}")
    job = status_response.json()

    print(f"Status: {job['status']}")

    if job["status"] == "completed":
        print(f"Reports: {job['report_files']}")
        break
    elif job["status"] == "failed":
        print(f"Error: {job['error']}")
        break

    time.sleep(2)
```

---

## 🎯 Interview Talking Points

### Architecture
> "I built a FastAPI web interface on top of the scanner to provide a complete product experience. It includes a beautiful UI for launching scans, a real-time dashboard for monitoring, and a full REST API for programmatic access."

### Technology Stack
- **Backend**: FastAPI (async Python web framework)
- **Frontend**: Vanilla JavaScript with modern CSS (no framework needed)
- **API**: RESTful with OpenAPI/Swagger documentation
- **Real-time Updates**: Polling-based status tracking
- **Background Tasks**: Async scan execution

### Key Features
1. **User-friendly UI**: No command-line knowledge required
2. **Real-time monitoring**: Dashboard updates automatically
3. **API-first design**: Can be integrated into CI/CD or other tools
4. **Professional presentation**: Looks like a production SaaS product

### Production Readiness
> "The web interface is production-ready with features like:
> - Health check endpoint for load balancers
> - Background task processing for long-running scans
> - Proper error handling and validation
> - Interactive API documentation
> - File size formatting and timestamps
> - Responsive design"

---

## 🔧 Configuration

### Change Port

Edit `app.py`:
```python
uvicorn.run(app, host="0.0.0.0", port=8000)  # Change 8000 to your port
```

### Enable CORS (for external frontends)

Add to `app.py`:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Production Deployment

Use Gunicorn with uvicorn workers:
```bash
pip install gunicorn
gunicorn app:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

---

## 📁 Project Structure

```
security-vulnerability-scanner/
├── app.py                    # FastAPI application
├── templates/
│   ├── index.html           # Home page (scan launcher)
│   └── dashboard.html       # Dashboard (monitoring)
├── static/                  # Static files (CSS, JS, images)
├── reports/                 # Generated reports
├── uploads/                 # Uploaded files (future feature)
└── src/                     # Scanner core logic
```

---

## 🎨 UI Screenshots

### Home Page
- Clean, gradient design
- Form-based scan configuration
- Real-time status updates
- Direct report links

### Dashboard
- Statistics cards
- Recent scans table with status badges
- Reports table with file info
- Refresh button for manual updates

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find process using port 8000
lsof -ti:8000

# Kill process
kill -9 $(lsof -ti:8000)

# Or use a different port
python app.py --port 8001
```

### Reports Not Showing
- Check that `reports/` directory exists
- Ensure scanner is generating reports successfully
- Check file permissions

### Scan Fails
- Verify repository path exists
- Check scanner dependencies are installed
- Review scan logs in dashboard

---

## 🚀 Future Enhancements

Potential additions for production:
- [ ] User authentication (JWT tokens)
- [ ] Database for persistent scan history
- [ ] WebSocket for real-time updates (instead of polling)
- [ ] File upload for scanning ZIP archives
- [ ] Scheduled scans (cron-like)
- [ ] Email notifications on scan completion
- [ ] Multi-tenancy support
- [ ] Rate limiting
- [ ] Prometheus metrics endpoint
- [ ] Docker container scanning via API

---

## 📞 API Reference

Full API documentation available at: **http://localhost:8000/docs**

This includes:
- Interactive API explorer (Swagger UI)
- Request/response schemas
- Try-it-out functionality
- Code generation for multiple languages

---

## ✅ Summary

You now have a **complete, production-ready web interface** for your security scanner:

✨ **Beautiful UI** - Professional design that looks like a SaaS product
⚡ **Fast & Async** - Built on FastAPI for high performance
📊 **Real-time Dashboard** - Monitor scans and reports in real-time
🔌 **REST API** - Integrate with CI/CD or other tools
📖 **Auto-generated Docs** - OpenAPI/Swagger documentation
🎯 **Interview-ready** - Demonstrates full-stack capabilities

**This transforms your CLI tool into a complete product!** 🎉
