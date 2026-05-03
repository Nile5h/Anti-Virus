import logging 

logging.basicConfig(
    filename='scan_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s  %(meggage)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_event(message, level='INFO'):
    if level == 'INFO':
        logging.info(message)
    elif level == 'MARNING':
        logging.warning(message)
    elif level == 'ERROR':
        logging.error(message)
    print(f"[{level}] {message}")

log_event("Antivirus engine started.")
log_event("Scanning directory: C:\\Users\\Public", "INFO")
log_event("Threat detected: EICAR_Test_File", "WARNING")
log_event("File moved to Quarantine.", "INFO")