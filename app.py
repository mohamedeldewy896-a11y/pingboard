import logging
import os
 
from flask import Flask, jsonify, render_template, request
 
import checker
 
app = Flask(__name__)
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
 
# A public checker must not probe internal networks (SSRF protection).
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE", "0") == "1"
 
 
@app.route("/")
def home():
    return render_template("index.html")
 
 
@app.route("/health")
def health():
    return jsonify(status="ok")          # the load balancer calls this later
 
 
@app.route("/check")
def check():
    host = request.args.get("host", "example.com").strip()
    try:
        port = checker.validate_port(request.args.get("port", "443"))
        result = checker.run_check(host, port, allow_private=ALLOW_PRIVATE)
    except checker.CheckError as exc:
        return jsonify(error=str(exc)), 400
    client = request.headers.get("X-Real-IP", request.remote_addr)
    app.logger.info("check host=%s port=%s tcp=%s client=%s",
                    host, port, result.get("tcp"), client)
    return jsonify(result)
 
 
if __name__ == "__main__":
    # Development only. Bind to localhost; never expose this server directly.
    app.run(host="127.0.0.1", port=5000)
