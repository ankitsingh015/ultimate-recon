#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
from datetime import datetime

try:
    from flask import Flask, render_template, send_from_directory, jsonify, request
except ImportError:
    os.system("pip3 install flask -q")
    from flask import Flask, render_template, send_from_directory, jsonify, request

app = Flask(__name__)

WORKSPACES_DIR = Path(__file__).parent.parent / "workspaces"
WORKSPACES_DIR.mkdir(exist_ok=True)


def get_workspaces():
    workspaces = []
    if not WORKSPACES_DIR.exists():
        return workspaces
    for d in sorted(WORKSPACES_DIR.iterdir()):
        if d.is_dir():
            meta = {}
            meta_file = d / "target.yaml"
            if meta_file.exists():
                with open(meta_file) as f:
                    meta = json.load(f)
            chat_count = 0
            chat_file = d / "chat.jsonl"
            if chat_file.exists():
                chat_count = sum(1 for _ in open(chat_file) if _.strip())
            report_exists = (d / "report.html").exists()
            workspaces.append({
                "name": d.name,
                "meta": meta,
                "chat_count": chat_count,
                "has_report": report_exists,
                "path": str(d),
            })
    return workspaces


@app.route("/")
def index():
    workspaces = get_workspaces()
    return render_template("index.html", workspaces=workspaces)


@app.route("/workspace/<name>")
def workspace(name):
    ws_path = WORKSPACES_DIR / name
    if not ws_path.exists():
        return "Workspace not found", 404

    meta = {}
    meta_file = ws_path / "target.yaml"
    if meta_file.exists():
        with open(meta_file) as f:
            meta = json.load(f)

    session_log = []
    session_file = ws_path / "session.jsonl"
    if session_file.exists():
        with open(session_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        session_log.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    all_results = {}
    results_dir = ws_path / "all_results"
    if results_dir.exists():
        for f in sorted(results_dir.iterdir()):
            if f.is_file():
                try:
                    size = f.stat().st_size
                    all_results[f.name] = size
                except Exception:
                    pass

    screenshots = []
    screenshots_dir = ws_path / "screenshots"
    if screenshots_dir.exists():
        screenshots = [s.name for s in sorted(screenshots_dir.glob("*.png"))[:20]]

    analysis_files = []
    analysis_dir = ws_path / "analysis"
    if analysis_dir.exists():
        analysis_files = sorted([f.name for f in analysis_dir.iterdir() if f.is_file()])

    report_exists = (ws_path / "report.html").exists()

    return render_template("workspace.html",
        name=name, meta=meta, session_log=session_log[-200:],
        all_results=all_results, screenshots=screenshots,
        analysis_files=analysis_files, report_exists=report_exists,
        ws_path=str(ws_path)
    )


@app.route("/workspace/<name>/chat")
def workspace_chat(name):
    ws_path = WORKSPACES_DIR / name
    if not ws_path.exists():
        return "Workspace not found", 404
    return render_template("chat.html", name=name)


@app.route("/api/workspace/<name>/chat")
def api_chat(name):
    ws_path = WORKSPACES_DIR / name
    chat_file = ws_path / "chat.jsonl"
    messages = []
    if chat_file.exists():
        with open(chat_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        messages.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return jsonify(messages)


@app.route("/api/workspace/<name>/chat", methods=["POST"])
def api_chat_post(name):
    ws_path = WORKSPACES_DIR / name
    chat_file = ws_path / "chat.jsonl"
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "message required"}), 400
    entry = {
        "role": "user",
        "message": data["message"],
        "timestamp": datetime.utcnow().isoformat()
    }
    with open(chat_file, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return jsonify(entry), 201


@app.route("/workspace/<name>/report")
def workspace_report(name):
    ws_path = WORKSPACES_DIR / name
    report_file = ws_path / "report.html"
    if report_file.exists():
        return send_from_directory(str(ws_path), "report.html")
    return "Report not generated yet. Run the full pipeline first.", 404


@app.route("/workspace/<name>/raw/<filename>")
def workspace_raw(name, filename):
    ws_path = WORKSPACES_DIR / name
    file_path = ws_path / "all_results" / filename
    if file_path.exists():
        return send_from_directory(str(file_path.parent), file_path.name)
    return "File not found", 404


@app.route("/workspace/<name>/analysis/<filename>")
def workspace_analysis(name, filename):
    ws_path = WORKSPACES_DIR / name
    file_path = ws_path / "analysis" / filename
    if file_path.exists():
        return send_from_directory(str(file_path.parent), file_path.name)
    return "File not found", 404


@app.route("/workspace/<name>/screenshots/<filename>")
def workspace_screenshot(name, filename):
    ws_path = WORKSPACES_DIR / name
    file_path = ws_path / "screenshots" / filename
    if file_path.exists():
        return send_from_directory(str(file_path.parent), file_path.name)
    return "File not found", 404


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Ultimate Recon Web UI")
    print(f"  http://{host}:{port}")
    print(f"  Workspaces: {WORKSPACES_DIR}\n")
    app.run(host=host, port=port, debug=False)
