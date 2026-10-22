
from flask import Flask, request, redirect, url_for, render_template_string
import re

app = Flask(__name__)
report = None

# Regex patterns
PATTERNS = {
    "ERROR": re.compile(r"\bERROR\b|\bFATAL\b", re.I),
    "WARNING": re.compile(r"\bWARN(?:ING)?\b", re.I),
    "INFO": re.compile(r"\bINFO\b", re.I)
}
SUSPICIOUS = re.compile(
    r"failed login|unauthorized|invalid password", re.I
)

# HTML and CSS design
PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>LogGuard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{margin:0;font-family:Arial;background:#f3f6fb;color:#1f2937}
nav,header,footer{text-align:center;padding:18px}
nav{background:#172554}
nav a{color:white;margin:12px;text-decoration:none;font-weight:bold}
header{background:#1d4ed8;color:white;padding:28px}
main{max-width:950px;margin:25px auto;padding:0 15px}
.card{background:white;padding:20px;margin-bottom:16px;
border-radius:10px;box-shadow:0 3px 12px #0001}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.number{font-size:28px;font-weight:bold}
button,.btn{background:#1d4ed8;color:white;padding:11px 16px;
border:0;border-radius:6px;text-decoration:none;cursor:pointer}
.log{background:#f8fafc;padding:12px;margin:10px 0;
border-left:5px solid #94a3b8;overflow-wrap:anywhere}
.ERROR{border-color:#dc2626}.WARNING{border-color:#d97706}
.INFO{border-color:#16a34a}
footer{color:#64748b}
</style>
</head>
<body>
<nav>
<a href="/">Home</a>
<a href="/dashboard">Dashboard</a>
<a href="/logs">Log Details</a>
</nav>
<header>
<h1>LogGuard</h1>
<p>Automated Log File Analysis Using Regular Expressions</p>
</header>
<main>
{% if page == "home" %}
<div class="card">
<h2>Analyze Your Log File</h2>
<p>Upload a .txt or .log file to find errors and suspicious activity.</p>
<form action="/upload" method="POST" enctype="multipart/form-data">
<input type="file" name="logfile" accept=".txt,.log" required>
<br><br><button>Upload and Analyze</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
</div>
<div class="card">
<h3>How it works</h3>
<p>1. Upload a log file.</p>
<p>2. Regex checks each line.</p>
<p>3. View the report and log details.</p>
</div>
{% elif report %}
{% if page == "dashboard" %}
<div class="card"><h2>Analysis Dashboard</h2>
<p>Log analysis completed successfully.</p></div>
<div class="cards">
{% for name, value in report.counts.items() %}
<div class="card">{{ name }}<div class="number">{{ value }}</div></div>
{% endfor %}
</div>
<div class="card"><a class="btn" href="/logs">View Log Details</a></div>
{% else %}
<div class="card"><h2>Log Details</h2>
{% for e in report.entries %}
<div class="log {{ e.category }}">
<b>{{ e.category }}</b>
{% if e.suspicious %} | <b>SUSPICIOUS</b>{% endif %}
<p>Line {{ e.number }}: {{ e.text }}</p>
</div>
{% else %}
<p>The uploaded file is empty.</p>
{% endfor %}
</div>
{% endif %}
{% else %}
<div class="card"><p>Please upload a log file first.</p></div>
{% endif %}
</main>
<footer>TOC Case Study 8 | LogGuard Project</footer>
</body>
</html>
"""

def analyze(text):
    entries = []
    for n, line in enumerate(text.splitlines(), 1):
        category = next(
            (name for name, pattern in PATTERNS.items()
             if pattern.search(line)), "OTHER"
        )
        entries.append({
            "number": n,
            "text": line,
            "category": category,
            "suspicious": bool(SUSPICIOUS.search(line))
        })

    return {
        "entries": entries,
        "counts": {
            "Total Lines": len(entries),
            "Errors": sum(e["category"] == "ERROR" for e in entries),
            "Warnings": sum(e["category"] == "WARNING" for e in entries),
            "Info Messages": sum(e["category"] == "INFO" for e in entries),
            "Suspicious": sum(e["suspicious"] for e in entries)
        }
    }

def show(page, message=""):
    return render_template_string(
        PAGE, page=page, report=report, message=message
    )

@app.route("/")
def home():
    return show("home", request.args.get("message", ""))

@app.route("/upload", methods=["POST"])
def upload():
    global report
    file = request.files.get("logfile")

    if not file or not file.filename:
        return redirect(url_for("home", message="Please select a file."))

    if not file.filename.lower().endswith((".txt", ".log")):
        return redirect(url_for("home", message="Upload a .txt or .log file."))

    try:
        text = file.stream.read(2 * 1024 * 1024 + 1)
        if len(text) > 2 * 1024 * 1024:
            return redirect(url_for("home", message="Maximum file size is 2 MB."))
        report = analyze(text.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return redirect(url_for("home", message="Please upload a UTF-8 text file."))

    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    return show("dashboard") if report else redirect(url_for("home"))

@app.route("/logs")
def logs():
    return show("logs") if report else redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
