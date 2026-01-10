from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any
import asyncio

from scanners.headers_scan import scan_headers
from scanners.api_key_scan import scan_api_keys
from scanners.data_leak_scan import scan_data_leaks
from scanners.zap_active_scan import run_active_scan
from report_generator import generate_report_for_frontend
from utils.zap_manager import start_zap

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
        
        return {
            "status": "completed",
            "scan_type": "passive",
            "report": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/active")
async def active_scan(req: ScanRequest) -> Dict[str, Any]:
    try:
        url = str(req.target)
        
        active_res = await asyncio.to_thread(run_active_scan, url)
        
        report = generate_report_for_frontend(
            target=url,
            active_results=active_res
        )
        
        return {
            "status": "completed",
            "scan_type": "active",
            "report": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))