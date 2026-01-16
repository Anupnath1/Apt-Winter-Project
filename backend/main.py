import asyncio
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from fastapi.responses import JSONResponse

# --- IMPORTS ---
# Ensure these paths match your project structure
from backend.scanners.headers_scan import scan_headers
from backend.scanners.api_key_scan import scan_api_keys
from backend.scanners.data_leak_scan import scan_data_leaks
# CHANGED: Import the class instead of the function
from backend.scanners.zap_active_scan import ZAPScanner 
from backend.report_generator import generate_report_for_frontend
from backend.utils.zap_manager import start_zap

app = FastAPI(title="APT Security Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: HttpUrl
    username: Optional[str] = None
    password: Optional[str] = None
    tenant: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "ok"}

@app.on_event("startup")
def startup_event():
    # Ensure ZAP is running before we start receiving requests
    start_zap()

@app.post("/scan/passive")
async def passive_scan(req: ScanRequest) -> Dict[str, Any]:
    """
    Runs lightweight passive checks (Headers, API Keys, Leaks).
    Does not require ZAP Active Scanner.
    """
    try:
        url = str(req.target)
        # Run synchronous scans in threads to avoid blocking the event loop
        headers_task = asyncio.to_thread(scan_headers, url)
        api_task = asyncio.to_thread(scan_api_keys, url)
        leak_task = asyncio.to_thread(scan_data_leaks, url=url)
        
        headers_res, api_res, leak_res = await asyncio.gather(
            headers_task, api_task, leak_task
        )
        
        report = generate_report_for_frontend(
            target=url,
            headers_results=headers_res,
            api_results=api_res,
            data_leak_results=leak_res
        )
        return {"status": "completed", "scan_type": "passive", "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Passive scan failed: {str(e)}")

# In main.py

class ScanRequest(BaseModel):
    target: HttpUrl
    username: Optional[str] = None
    password: Optional[str] = None
    tenant: Optional[str] = None
    manual_token: Optional[str] = None  # <--- NEW FIELD

# ... inside active_scan function ...

@app.post("/scan/active")
async def active_scan(req: ScanRequest) -> Dict[str, Any]:
    url = str(req.target)
    
    # Credentials object
    creds = {
        "username": req.username,
        "password": req.password,
        "tenant": req.tenant or ""
    }

    def _execute_zap_workflow(target_url: str, credentials: Dict, token: Optional[str]):
        scanner = ZAPScanner(target_url)
        scanner.check_connection()
        scanner.setup_context()

        # Pass both credentials AND the manual token
        # If token is present, scanner will use it and ignore credentials
        scanner.perform_login_and_hook(credentials, manual_token=token)

        scanner.run_scans()
        return scanner.get_results()

    try:
        # Pass req.manual_token to the thread
        active_alerts = await asyncio.to_thread(_execute_zap_workflow, url, creds, req.manual_token)
        
        report = generate_report_for_frontend(target=url, active_results=active_alerts)
        return {"status": "completed", "scan_type": "active", "report": report}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

        # Scan Phase
        scanner.run_scans()
        
        # Result Phase
        return scanner.get_results()

    try:
        # 3. Run the blocking ZAP workflow in a separate thread
        active_alerts = await asyncio.to_thread(_execute_zap_workflow, url, creds)
        
        # 4. Generate Report
        report = generate_report_for_frontend(target=url, active_results=active_alerts)
        
        return {"status": "completed", "scan_type": "active", "report": report}

    except RuntimeError as re:
        # Handle known errors (ZAP connection, Login failure)
        raise HTTPException(status_code=502, detail=str(re))
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(status_code=500, detail=f"Active scan error: {str(e)}")
    
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_details = exc.errors()
    print("\n--- VALIDATION ERROR ---")
    print(f"URL: {request.url}")
    print(f"Body: {error_details}")
    print("------------------------\n")
    return JSONResponse(
        status_code=422,
        content={"detail": error_details, "body": str(exc)},
    )