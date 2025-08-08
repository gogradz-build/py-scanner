#!/usr/bin/env python3
"""
scanner.py
Run Bandit (SAST), pip-audit (SCA), detect-secrets (Secrets) on a target path or git repo.
Produces a combined JSON report in reports/.
"""

import argparse, os, json, tempfile, shutil, subprocess, datetime
from pathlib import Path

def run_cmd(cmd, cwd=None):
    """Run shell command, return (returncode, stdout, stderr)."""
    proc = subprocess.run(cmd, shell=True, cwd=cwd,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    return proc.returncode, out, err

def run_bandit(target_path, run_cmd_fn=run_cmd):
    cmd = f"bandit -r \"{target_path}\" -f json"
    rc, out, err = run_cmd_fn(cmd, cwd=target_path)
    if out and out.strip():
        try:
            return json.loads(out)
        except Exception:
            return {"error": "bandit-json-parse-failed", "stdout": out, "stderr": err}
    return {"results": [], "note": "no-output", "stderr": err}

def run_pip_audit(target_path, run_cmd_fn=run_cmd):
    req = Path(target_path) / "requirements.txt"
    if not req.exists():
        return {"skipped": True, "reason": "no requirements.txt found"}
    cmd = f"pip-audit --requirement \"{req}\" --format json"
    rc, out, err = run_cmd_fn(cmd, cwd=target_path)
    if out and out.strip():
        try:
            return json.loads(out)
        except Exception:
            return {"error": "pip-audit-json-parse-failed", "stdout": out, "stderr": err}
    return {"vulns": [], "note": "no-output", "stderr": err}

def run_detect_secrets(target_path, run_cmd_fn=run_cmd):
    cmd = f"detect-secrets scan \"{target_path}\" --all-files"
    rc, out, err = run_cmd_fn(cmd, cwd=target_path)
    if out and out.strip():
        try:
            return json.loads(out)
        except Exception:
            return {"error": "detect-secrets-json-parse-failed", "stdout": out, "stderr": err}
    return {"results": {}, "note": "no-output", "stderr": err}

def clone_repo(repo_url, dest_dir, run_cmd_fn=run_cmd):
    cmd = f"git clone --depth 1 \"{repo_url}\" \"{dest_dir}\""
    rc, out, err = run_cmd_fn(cmd)
    if rc != 0:
        raise RuntimeError(f"git clone failed: {err.strip() or out.strip()}")
    return dest_dir

def scan_target(target, output_dir="reports", run_cmd_fn=run_cmd):
    tmpdir = None
    is_temp = False
    try:
        if target.startswith("http://") or target.startswith("https://") or target.endswith(".git"):
            tmpdir = tempfile.mkdtemp(prefix="scanrepo_")
            is_temp = True
            print(f"[+] Cloning {target} into {tmpdir} ...")
            clone_repo(target, tmpdir, run_cmd_fn=run_cmd_fn)
            target_path = tmpdir
        else:
            target_path = os.path.abspath(target)
            if not os.path.exists(target_path):
                raise FileNotFoundError(f"target path does not exist: {target_path}")

        print(f"[+] Running Bandit (SAST) ...")
        bandit_res = run_bandit(target_path, run_cmd_fn=run_cmd_fn)

        print(f"[+] Running pip-audit (SCA) ...")
        pip_audit_res = run_pip_audit(target_path, run_cmd_fn=run_cmd_fn)

        print(f"[+] Running detect-secrets (Secrets) ...")
        secrets_res = run_detect_secrets(target_path, run_cmd_fn=run_cmd_fn)

        report = {
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "target": target,
            "bandit": bandit_res,
            "pip_audit": pip_audit_res,
            "detect_secrets": secrets_res,
        }

        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        outfile = Path(output_dir) / f"scan_report_{ts}.json"
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to: {outfile}")
        return str(outfile)
    finally:
        if is_temp and tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)

def main():
    p = argparse.ArgumentParser(description="Small Python security scanner (bandit + pip-audit + detect-secrets)")
    p.add_argument("--target", "-t", required=True, help="Local path or git repo URL to scan")
    p.add_argument("--output", "-o", default="reports", help="Output reports directory")
    args = p.parse_args()
    try:
        scan_target(args.target, args.output)
    except Exception as e:
        print("[ERROR]", e)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
