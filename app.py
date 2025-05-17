from flask import Flask, request, redirect, url_for, render_template_string, flash
import subprocess
import shlex
import datetime
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")

# ---------------------------------------------------------------------------
# Templates (rendered inline for single‑file simplicity)
# ---------------------------------------------------------------------------
INDEX_TMPL = """
<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Host Authentication Enumerator</title>
    <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
  </head>
  <body class=\"bg-light\">
    <div class=\"container py-5\">
      <h1 class=\"mb-4 text-center\">Host Authentication Enumerator</h1>
      <form method=\"post\" action=\"{{ url_for('run_enum') }}\" class=\"card shadow-sm p-4\">
        <div class=\"mb-3\">
          <label for=\"ips\" class=\"form-label fw-bold\">IP Addresses / Ranges</label>
          <textarea class=\"form-control\" id=\"ips\" name=\"ips\" rows=\"3\" placeholder=\"192.168.1.10-15, 192.168.1.50\"></textarea>
          <div class=\"form-text\">Separate entries with <strong>spaces or commas</strong>. Use a dash for inclusive ranges.</div>
        </div>
        <div class=\"row g-3 mb-3\">
          <div class=\"col-md-4\">
            <label class=\"form-label fw-bold\" for=\"username\">Username</label>
            <input type=\"text\" class=\"form-control\" id=\"username\" name=\"username\" required>
          </div>
          <div class=\"col-md-4\">
            <label class=\"form-label fw-bold\" for=\"password\">Password</label>
            <input type=\"password\" class=\"form-control\" id=\"password\" name=\"password\" required>
          </div>
          <div class=\"col-md-4\">
            <label class=\"form-label fw-bold\" for=\"domain\">Domain</label>
            <input type=\"text\" class=\"form-control\" id=\"domain\" name=\"domain\" required>
          </div>
        </div>
        <div class=\"row g-3 mb-3\">
          <div class=\"col-md-4 form-check\">
            <input class=\"form-check-input\" type=\"checkbox\" id=\"smb\" name=\"smb\" checked>
            <label class=\"form-check-label fw-bold\" for=\"smb\">SMB</label>
          </div>
          <div class=\"col-md-4 form-check\">
            <input class=\"form-check-input\" type=\"checkbox\" id=\"winrm\" name=\"winrm\" checked>
            <label class=\"form-check-label fw-bold\" for=\"winrm\">WinRM</label>
          </div>
          <div class=\"col-md-4 form-check\">
            <input class=\"form-check-input\" type=\"checkbox\" id=\"rdp\" name=\"rdp\" checked>
            <label class=\"form-check-label fw-bold\" for=\"rdp\">RDP</label>
          </div>
        </div>
        <div class=\"mb-3 col-md-3\">
          <label class=\"form-label fw-bold\" for=\"threads\">Threads</label>
          <input type=\"number\" class=\"form-control\" id=\"threads\" name=\"threads\" value=\"10\" min=\"1\" max=\"50\">
        </div>
        <button type=\"submit\" class=\"btn btn-primary w-100\">Run Enumeration</button>
      </form>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <div class=\"alert alert-danger mt-4\">{{ messages[0] }}</div>
        {% endif %}
      {% endwith %}
    </div>
  </body>
</html>
"""

RESULT_TMPL = """
<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>Enumeration Results</title>
    <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
    <style> pre { background:#f8f9fa; padding:1rem; border-radius:.5rem; } </style>
  </head>
  <body class=\"bg-light\">
    <div class=\"container py-5\">
      <h1 class=\"mb-4 text-center\">Enumeration Results</h1>
      <p class=\"text-muted\">Started at {{ start_time }} • Duration: {{ duration }}</p>
      <pre>{{ output }}</pre>
      <div class=\"text-center mt-4\">
        <a href=\"{{ url_for('index') }}\" class=\"btn btn-secondary\">⬅︎ Start New Run</a>
      </div>
    </div>
  </body>
</html>
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_TMPL)


@app.route("/run", methods=["POST"])
def run_enum():
    # Collect & basic-sanitize form data
    ips_raw = request.form.get("ips", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")  # keep as typed
    domain = request.form.get("domain", "").strip()
    threads = request.form.get("threads", "10").strip()
    smb_flag = "--smb" if request.form.get("smb") else ""
    winrm_flag = "--winrm" if request.form.get("winrm") else ""
    rdp_flag = "--rdp" if request.form.get("rdp") else ""

    if not ips_raw or not username or not password or not domain:
        flash("All fields are required.")
        return redirect(url_for("index"))

    # Convert comma & whitespace‑separated list to individual tokens
    ip_tokens = re.split(r"[\s,]+", ips_raw)
    ip_tokens = [t for t in ip_tokens if t]  # drop empties
    ip_args = " ".join(shlex.quote(t) for t in ip_tokens)

    # Build CLI command
    script_path = os.path.join(os.path.dirname(__file__), "enum_hosts_smb_winrm_rdp.py")
    cmd = (
        f"python3 {shlex.quote(script_path)} -i {ip_args} "
        f"-u {shlex.quote(username)} -p {shlex.quote(password)} -d {shlex.quote(domain)} "
        f"{smb_flag} {winrm_flag} {rdp_flag} --threads {threads}"
    )

    start_time = datetime.datetime.now()
    try:
        completed = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=None)
        output = completed.stdout + "\n" + completed.stderr
    except Exception as exc:
        output = f"Exception while running enumeration: {exc}"

    duration = datetime.datetime.now() - start_time
    return render_template_string(
        RESULT_TMPL,
        output=output,
        start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration,
    )


# ---------------------------------------------------------------------------
# Entry‑point helper for `python app.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)