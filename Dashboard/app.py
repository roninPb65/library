from flask import Flask, render_template, request, Response, jsonify, stream_with_context

import subprocess
import threading
import time
import json
import os


# Elasticsearch (local)
from elasticsearch import Elasticsearch

app = Flask(__name__)

# --- WIDS PROCESS HANDLER ---
process = None

# --- ELASTICSEARCH CONFIG ---
es = Elasticsearch("http://localhost:9200")   # adjust if ES is remote
INDEX = "wids-logs"                           # change to your index name


# ---------------------------
#       ROOT DASHBOARD
# ---------------------------
@app.route('/')
def index():
    return render_template("index.html")


# ---------------------------
#       START WIDS
# ---------------------------
@app.route('/start', methods=['POST'])
def start_wids():
    global process

    interface = request.form.get("interface")
    enable_monitor = request.form.get("enable_monitor") == "on"

    cmd = ["sudo", "python3", "enhanced_wids.py", "-i", interface]

    if enable_monitor:
        cmd.append("--enable-monitor")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    return """
        <script>
            alert("WIDS Started");
            window.location.href = "/";
        </script>
    """


# ---------------------------
#       STOP WIDS
# ---------------------------
@app.route('/stop', methods=['POST'])
def stop_wids():
    global process

    if process:
        process.terminate()
        process = None

    return """
        <script>
            alert("WIDS Stopped");
            window.location.href = "/";
        </script>
    """


# ---------------------------
#       STREAM LIVE LOGS
# ---------------------------
@app.route('/logs')
def stream_logs():
    def generate():
        global process
        if not process or not process.stdout:
            yield "data: No process running\n\n"
            return

        while True:
            line = process.stdout.readline()
            if not line:
                # End of stream
                break
            yield f"data: {line.decode('utf-8') if isinstance(line, bytes) else line}\n\n"

    # Use stream_with_context to ensure Flask context is kept
    return Response(stream_with_context(generate()), mimetype='text/event-stream')


# -----------------------------------------------------------------------------
#                            ATTACK DASHBOARD ROUTES
# -----------------------------------------------------------------------------

@app.route('/wep-attacks')
def wep_attacks():
    return render_template("attack_page.html", attack_key="wep", title="WEP Attacks")

@app.route('/tkip-attacks')
def tkip_attacks():
    return render_template("attack_page.html", attack_key="tkip", title="TKIP Attacks")

@app.route('/evil-twin')
def evil_twin():
    return render_template("attack_page.html", attack_key="evil", title="Evil Twin Attacks")

@app.route('/beacon-flood')
def beacon_flood():
    return render_template("attack_page.html", attack_key="beacon", title="Beacon Flood")

@app.route('/probe-flood')
def probe_flood():
    return render_template("attack_page.html", attack_key="probe", title="Probe Flood")

@app.route('/deauth-flood')
def deauth_flood():
    return render_template("attack_page.html", attack_key="deauth", title="Deauthentication Flood")


# -----------------------------------------------------------------------------
#                            SINGLE ES QUERY ENDPOINT
# -----------------------------------------------------------------------------

@app.route('/alerts_data')
def alerts_data():
    logfile = os.path.join(os.path.dirname(__file__), "logs", "log.json")

    def generate():
        try:
            while True:
                alerts_count = {}
                with open(logfile, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        ts = entry.get("timestamp", "")
                        ts = ts[:19]  # optional: truncate milliseconds
                        alerts_count[ts] = alerts_count.get(ts, 0) + 1

                # Send the last 20 timestamps
                sorted_ts = sorted(alerts_count.keys())
                for ts in sorted_ts[-20:]:
                    payload = json.dumps({"time": ts, "count": alerts_count[ts]})
                    yield f"data: {payload}\n\n"

                time.sleep(2)  # push every 2 seconds

        except GeneratorExit:
            print("Client disconnected from /alerts_data")

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
    
@app.route('/es-query')
def es_query():
    attack_key = request.args.get("type", "")

    # Map attack categories to attack_type values inside your logs
    mapping = {
        "wep": ["wesside_ng", "wep_broadcast_data"],
        "tkip": ["tkiptun_ng"],
        "evil": ["evil_twin"],
        "beacon": ["beacon_flood"],
        "probe": ["probe_flood"],
        "deauth": ["deauth_flood"]
    }

    attack_types = mapping.get(attack_key, [])

    logfile = os.path.join(os.path.dirname(__file__), "logs", "log.json")

    try:
        logs = []
        with open(logfile, "r") as f:
            for line in f:
                line = line.strip()
                if line:  # skip empty lines
                    logs.append(json.loads(line))

        # Filter logs by attack types
        filtered = [
            entry for entry in logs
            if entry.get("attack_type") in attack_types
        ]

        # Sort newest → oldest by timestamp
        filtered = sorted(filtered, key=lambda x: x.get("timestamp", ""), reverse=True)

        return jsonify(filtered)

    except FileNotFoundError:
        return jsonify({"error": "Log file not found"}), 404
    except json.JSONDecodeError as e:
        return jsonify({"error": f"JSON parse error: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------------
#              MAIN
# -------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

