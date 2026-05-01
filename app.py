import hashlib
import yara, os


def get_file_hash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4896), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
def scan_file(file_to_scan, database_file):
    file_hash = get_file_hash(file_to_scan)

    with open(database_file, "r") as db:
        signatures = db.read().splitlines()
    
    if file_hash in signatures:
        print(f"Alert: {file_to_scan} is Malicious")
    else:
        print(f"{file_to_scan} is Clean.")


# scan using yara patters
def heuristic_scan(target_file, rules_file):
    rules = yara.compile(filepath=rules_file)

    matches = rules.match(target_file)

    if matches:
        print(f"!! HEURISTIC ALERT: {target_file} triggered rules: {matches}")
        return True
    print("safe")
    return False

# if os.path.exists("a.txt"):
#     heuristic_scan("a.txt", "my_rules.yar")

# scan_file ("a.txt","signature.txt")


# scaning ram
import psutil

def list_running_processes():
    for proc in psutil.process_iter(['pid','name']):
        try:
            print(f"Scanning RAM for process: {proc.info['name']} (PID : {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print("passing")
            pass

# mathcing yara rules in ram
def scan_process_memory(pid, rule_path):
    try:
        rules = yara.compile(filepath=rule_path)
        matches = rules.match(pid=pid)
        if matches:
            print(f"!!! Memory treat detected in PID {pid}: {matches}")
        else:
            print(f"Process {pid} memory is clean. ")
    except yara.Error as e:
        print(f"Scan failed for PID {pid}: {e}")
    except psutil.AccessDenied:
        print(f"Access Denied: Run as Admin to scan PID {pid}[cite: 90].")

scan_process_memory(8252,"my_rules.yar")
# list_running_processes()