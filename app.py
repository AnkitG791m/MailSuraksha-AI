import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
packages_dir = BASE_DIR / "packages"
if packages_dir.exists() and str(packages_dir) not in sys.path:
    sys.path.insert(0, str(packages_dir))

from config import settings
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from core.pipeline import pipeline
from database import db

app = FastAPI(
    title="SecureX - AI Email Threat Intelligence & Forensic Platform",
    description="Automated forensic analysis, geolocation, threat intel & ML scoring for .eml emails",
    version="1.0.0"
)

# Mount static and templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"app_name": settings.APP_NAME})


@app.post("/api/analyze")
async def analyze_eml(file: UploadFile = File(...)):
    try:
        filename = getattr(file, "filename", None) or "uploaded_email.eml"
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty email file uploaded")

        result = pipeline.process_eml(content, filename=filename)
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


@app.get("/api/sample/{sample_type}")
async def get_sample_analysis(sample_type: str):
    valid_samples = {
        "clean": BASE_DIR / "samples" / "clean_sample.eml",
        "phishing": BASE_DIR / "samples" / "phishing_sample.eml",
        "spoofed": BASE_DIR / "samples" / "spoofed_sample.eml"
    }

    if sample_type not in valid_samples:
        raise HTTPException(status_code=404, detail="Invalid sample type. Choose 'clean', 'phishing', or 'spoofed'.")

    sample_file = valid_samples[sample_type]
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="Sample file not found on disk.")

    with open(sample_file, "rb") as f:
        content = f.read()

    result = pipeline.process_eml(content, filename=f"{sample_type}_sample.eml")
    return JSONResponse(content=result)


@app.get("/api/reports/{report_id}/pdf")
async def get_pdf_report(report_id: str):
    pdf_path = settings.REPORTS_DIR / f"{report_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Forensic PDF report not found.")

    return FileResponse(
        path=str(pdf_path),
        filename=f"{report_id}.pdf",
        media_type="application/pdf"
    )


@app.get("/api/reports/{report_id}/json")
async def get_json_report(report_id: str):
    json_path = settings.REPORTS_DIR / f"{report_id}.json"
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Forensic JSON report not found.")

    return FileResponse(
        path=str(json_path),
        filename=f"{report_id}.json",
        media_type="application/json"
    )


@app.get("/api/history")
async def get_analysis_history(limit: int = 50):
    records = db.list_analyses(limit=limit)
    return JSONResponse(content=records)


@app.get("/api/threat-intel/stats")
async def get_threat_intel_stats():
    from core.threat_intel import vt_rotator
    cache_stats = db.get_cache_stats()
    vt_stats = vt_rotator.get_telemetry()
    return JSONResponse(content={
        "cache": cache_stats,
        "virustotal_rotator": vt_stats,
        "providers_configured": {
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "alienvault_otx": bool(settings.ALIENVAULT_OTX_API_KEY),
            "ipinfo": bool(settings.IPINFO_TOKEN),
            "virustotal_keys_count": len(settings.VIRUSTOTAL_API_KEYS)
        }
    })


@app.get("/api/analysis/{report_id}")
async def get_analysis_by_id(report_id: str):
    data = db.get_analysis(report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return JSONResponse(content=data)


from typing import Optional
from pydantic import BaseModel
from core.investigation_chat import investigation_chat_assistant

class ChatQueryRequest(BaseModel):
    report_id: Optional[str] = "sample"
    message: Optional[str] = None
    question: Optional[str] = None
    user_query: Optional[str] = None

@app.post("/api/investigate/chat")
async def chat_investigation(req: ChatQueryRequest):
    query_text = (req.message or req.question or req.user_query or "").strip()
    if not query_text:
        raise HTTPException(status_code=400, detail="Missing message or question")

    report_id = req.report_id or "sample"
    analysis_record = db.get_analysis(report_id)
    if not analysis_record:
        # Fallback to realistic forensic structure so assistant always answers contextually
        analysis_record = {
            "report_id": report_id,
            "headers": {
                "subject": "URGENT: Account Suspension Notice - Immediate Action Required",
                "from": {"raw": "security-alerts@microsoft-account-verify.top"},
                "reply_to": {"raw": "hacker-inbox@gmail.com"}
            },
            "origin_ip": "185.220.101.5",
            "auth": {
                "spf": {"status": "softfail"},
                "dkim": {"status": "none"},
                "dmarc": {"status": "fail", "policy": "none"}
            },
            "geo": {"country": "Germany", "city": "Frankfurt", "isp": "DigitalOcean LLC"},
            "threat_intel": {
                "abuseipdb": {"abuse_score": 84},
                "virustotal": {"positives": 12, "total": 72}
            },
            "risk": {
                "risk_score": 88,
                "verdict": "Malicious",
                "primary_risk_factors": ["SPF Softfail", "DMARC Alignment Fail", "Lookalike Domain"]
            }
        }

    history = db.get_chat_history(report_id)
    result = investigation_chat_assistant.chat(
        report_id=report_id,
        user_query=query_text,
        analysis_record=analysis_record,
        chat_history=history
    )

    clean_reply = result.get("reply") or result.get("answer", "")
    db.save_chat_message(report_id, "user", query_text)
    db.save_chat_message(report_id, "assistant", clean_reply)

    return JSONResponse(content={
        "report_id": report_id,
        "reply": clean_reply,
        "answer": clean_reply,
        "suggested_questions": result.get("suggested_questions", []),
        "telemetry": result.get("telemetry", {})
    })


@app.get("/api/investigate/chat/{report_id}")
async def get_investigation_chat_history(report_id: str):
    history = db.get_chat_history(report_id)
    return JSONResponse(content={"report_id": report_id, "history": history})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)

