import subprocess
import os
import json

def run_command(cmd, cwd=None, timeout=None):
    """Jalankan perintah dan kembalikan stdout, stderr, return code."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as e:
        return "", str(e), -1

def save_raw_output(workspace_dir, phase, tool_name, content, ext='txt'):
    """Simpan output mentah ke raw_logs/[phase]/[tool_name].[ext]"""
    raw_dir = os.path.join(workspace_dir, 'raw_logs', phase)
    os.makedirs(raw_dir, exist_ok=True)
    fname = f"{tool_name}.{ext}"
    fpath = os.path.join(raw_dir, fname)
    with open(fpath, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(content)
    return fpath

def load_json_output(filepath):
    """Muat file JSON jika ada."""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None