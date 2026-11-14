import os
import tempfile
from flask import Flask, request, abort

app = Flask(__name__)

def read_workspace_file(filename: str) -> str:
    # Uses TemporaryDirectory so sandbox file operations stay inside a writable path
    with tempfile.TemporaryDirectory() as base_dir:
        seed_path = os.path.join(base_dir, "welcome.txt")
        with open(seed_path, "w", encoding="utf-8") as f:
            f.write("public workspace file")

        # CWE-22: Direct os.path.join without realpath prefix check allows traversal
        target_path = os.path.join(base_dir, filename)
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()

@app.route("/files", methods=["GET"])
def get_file():
    filename = request.args.get("name", "welcome.txt")
    if not filename:
        abort(400)
    return read_workspace_file(filename), 200
