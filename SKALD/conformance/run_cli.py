"""Runs the SKALD command line over every conformance case.

    python3 run_cli.py BIN OUT_DIR            # run, collect outputs under OUT_DIR/<case>/
    python3 run_cli.py BIN --record           # run and overwrite ./expected/ (known-good build only)

Each case runs in a scratch copy, because the command line rewrites the key
files it is given. Run-specific text (paths, timings) is removed from
status.json so two builds can be compared byte for byte.
"""
import json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
KEEP = ["anonymized.csv", "equivalence_class_stats.json", "top_ola2_nodes.json", "parameter_grid.csv"]


def clean_status(raw, root):
    s = json.loads(raw)
    # Sized from the machine's free RAM, so it differs between hosts and runs.
    (s.get("outputs") or {}).pop("rows_per_chunk", None)
    text = json.dumps(s, indent=2, sort_keys=True).replace(root, "<ROOT>")
    return re.sub(r'"(elapsed|duration)[a-z_]*": [0-9.]+', r'"\1": 0', text) + "\n"


def run_case(binary, case, out_root):
    work = tempfile.mkdtemp(prefix="skald-conf-")
    try:
        os.makedirs(os.path.join(work, "data"))
        os.makedirs(os.path.join(work, "config"))
        shutil.copy(os.path.join(CASES, case, "data.csv"), os.path.join(work, "data", "data.csv"))
        shutil.copy(os.path.join(CASES, case, "config.json"), os.path.join(work, "config", "config.json"))
        shutil.copytree(os.path.join(CASES, case, "testkeys"), os.path.join(work, "keys"))
        p = subprocess.run([binary, "--root", work], capture_output=True, text=True)
        dest = os.path.join(out_root, case)
        shutil.rmtree(dest, ignore_errors=True)
        os.makedirs(dest)
        out = os.path.join(work, "output")
        for fn in KEEP:
            if os.path.exists(os.path.join(out, fn)):
                shutil.copy(os.path.join(out, fn), os.path.join(dest, fn))
        status = os.path.join(out, "status.json")
        if os.path.exists(status):
            with open(status) as f, open(os.path.join(dest, "status.json"), "w") as g:
                g.write(clean_status(f.read(), work))
        return p.returncode
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    binary = os.path.abspath(sys.argv[1])
    out_root = os.path.join(HERE, "expected") if "--record" in sys.argv else sys.argv[2]
    for case in sorted(os.listdir(CASES)):
        rc = run_case(binary, case, out_root)
        print(f"{case}: exit {rc}")


if __name__ == "__main__":
    main()
