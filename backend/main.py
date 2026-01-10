from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any
from utils.zap_manager import start_zap
from report_generator import (
    run_passive_scans_and_generate_report,
    run_active_scan_and_generate_report
)

app = FastAPI(title="APT Security Scanner API", version="1.0.0")


class ScanRequest(BaseModel):
    target: HttpUrl


@app.get("/health")
def health():
    return {"status": "ok"}


@app.on_event("startup")
def startup_event():
    start_zap()


@app.post("/scan/passive")
def passive_scan(req: ScanRequest) -> Dict[str, Any]:
    try:
        return {
            "status": "completed",
            "scan_type": "passive",
            "report": run_passive_scans_and_generate_report(
                target=str(req.target)
            )
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/active")
def active_scan(req: ScanRequest) -> Dict[str, Any]:
    try:
        return {
            "status": "completed",
            "scan_type": "active",
            "report": run_active_scan_and_generate_report(
                target=str(req.target)
            )
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
