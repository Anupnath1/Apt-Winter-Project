from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, Optional
import asyncio

# CORRECT IMPORTS:
from backend.scanners.headers_scan import scan_headers
from backend.scanners.api_key_scan import scan_api_keys
from backend.scanners.data_leak_scan import scan_data_leaks
from backend.scanners.zap_active_scan import run_active_scan
from backend.report_generator import generate_report_for_frontend

# Fix the double dot syntax error here:
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
    start_zap()

@app.post("/scan/passive")
async def passive_scan(req: ScanRequest) -> Dict[str, Any]:
    try:
        url = str(req.target)
        headers_task = asyncio.to_thread(scan_headers, url)
        api_task = scan_api_keys(url)
        leak_task = scan_data_leaks(url=url)
        
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/active")
async def active_scan(req: ScanRequest) -> Dict[str, Any]:
    try:
        url = str(req.target)
        auth_config = None
        if req.username and req.password:
            auth_config = {
                "username": req.username,
                "password": req.password,
                "tenant": req.tenant
            }
        
        active_res = await asyncio.to_thread(run_active_scan, url, auth_config)
        report = generate_report_for_frontend(target=url, active_results=active_res)
        
        return {"status": "completed", "scan_type": "active", "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))