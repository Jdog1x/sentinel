"""
sentinel/api/app.py
Flask REST API — scans, findings, AI chat, report download.
"""
from __future__ import annotations

import threading
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from sentinel.core.config import config
from sentinel.core.models import Report, Scan, ScanStatus, SessionLocal, init_db
from sentinel.core.scanner import ScanOrchestrator
from sentinel.llm.provider import get_provider
from sentinel.reports.pdf_generator import generate as generate_pdf


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = config.flask_secret_key
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    init_db()

    @app.get("/api/scans")
    def list_scans():
        db = SessionLocal()
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
        result = [s.to_dict() for s in scans]
        db.close()
        return jsonify(result)

    @app.post("/api/scans")
    def create_scan():
        data    = request.get_json(force=True)
        target  = data.get("target", "").strip()
        backend = data.get("llm_backend")
        fast    = data.get("fast", False)
        if not target:
            return jsonify({"error": "target is required"}), 400
        db   = SessionLocal()
        scan = Scan(target=target, status=ScanStatus.PENDING, llm_backend=backend)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_dict = scan.to_dict()
        db.close()

        def _run():
            ScanOrchestrator(llm_backend=backend).run_scan(target, fast=fast)

        threading.Thread(target=_run, daemon=True).start()
        return jsonify(scan_dict), 202

    @app.get("/api/scans/<scan_id>")
    def get_scan(scan_id: str):
        db = SessionLocal()
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        if not s:
            db.close()
            return jsonify({"error": "scan not found"}), 404
        result = s.to_dict()
        db.close()
        return jsonify(result)

    @app.delete("/api/scans/<scan_id>")
    def delete_scan(scan_id: str):
        db   = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            db.close()
            return jsonify({"error": "not found"}), 404
        db.delete(scan)
        db.commit()
        db.close()
        return jsonify({"deleted": scan_id})

    @app.post("/api/scans/<scan_id>/report")
    def create_report(scan_id: str):
        db = SessionLocal()
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        if not s:
            db.close()
            return jsonify({"error": "scan not found"}), 404
        try:
            pdf_path = generate_pdf(s)
            report   = Report(scan_id=scan_id, file_path=str(pdf_path))
            db.add(report)
            db.commit()
            db.refresh(report)
            report_dict = report.to_dict()
        except Exception as exc:
            db.close()
            return jsonify({"error": str(exc)}), 500
        db.close()
        return jsonify(report_dict), 201

    @app.get("/api/reports/<report_id>/download")
    def download_report(report_id: str):
        db     = SessionLocal()
        report = db.query(Report).filter(Report.id == report_id).first()
        db.close()
        if not report:
            return jsonify({"error": "not found"}), 404
        p = Path(report.file_path)
        if not p.exists():
            return jsonify({"error": "file missing"}), 404
        return send_file(str(p), as_attachment=True, download_name=p.name)

    @app.post("/api/chat")
    def chat():
        data     = request.get_json(force=True)
        messages = data.get("messages", [])
        scan_id  = data.get("scan_id")
        backend  = data.get("llm_backend")
        if not messages:
            return jsonify({"error": "messages are required"}), 400
        if scan_id:
            db   = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                ctx = f"\n\n[SCAN CONTEXT - target: {scan.target}]\n"
                if scan.raw_results and scan.raw_results.get("analysis"):
                    summary = scan.raw_results.get("analysis", {}).get("executive_summary", "")
                    ctx += f"Summary: {summary}\n"
                messages = list(messages)
                messages[-1]["content"] = ctx + messages[-1]["content"]
            db.close()
        try:
            provider = get_provider(backend)
            reply    = provider.chat(messages)
            return jsonify({"reply": reply})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "llm_backend": config.llm_backend})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=config.flask_port, debug=config.flask_debug)
