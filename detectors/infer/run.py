import subprocess

if __name__ == "__main__":
    res = subprocess.run(["python3", "detectors/infer/run_infer_vfc.py"], shell=False, timeout=100)