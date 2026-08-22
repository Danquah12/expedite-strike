import subprocess
import os
import glob
import logging

logger = logging.getLogger(__name__)

def run_bloodhound_ingest(target_ip="192.168.1.10", username="Administrator", password="Adomaa12@", domain="expedite.local"):
    try:
        data_dir = "/Backup/vuln_intel/app/data/bloodhound"
        os.makedirs(data_dir, exist_ok=True)
        
        # 1. Run BloodHound-Python
        cmd = [
            "bloodhound-python", "-u", username, "-p", password, 
            "-ns", target_ip, "-d", domain, "-c", "All", "--zip"
        ]
        
        logger.info(f"Running BH: {' '.join(cmd)}")
        # Subprocess to generate the BloodHound artifacts
        subprocess.run(cmd, cwd=data_dir, check=True)
        
        # 2. Extract ZIP
        extract_dir = os.path.join(data_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run("unzip -o *.zip -d extracted", shell=True, cwd=data_dir, check=True)
        
        # 3. Import via bloodhound-import natively into Neo4j
        json_files = glob.glob(os.path.join(extract_dir, "*.json"))
        
        import_cmd = [
            "sudo", "/root/vuln_intel/venv/bin/bloodhound-import", 
            "-du", "neo4j", "-dp", "Adomaa12@", 
            "-p", "7687", "-s", "bolt"
        ] + json_files
        
        subprocess.run(import_cmd, cwd=data_dir, check=True)
        
        return {"status": "success", "message": "BloodHound ingestion completely successfully!"}
    except Exception as e:
        logger.error(f"BH Ingest Error: {str(e)}")
        return {"status": "error", "message": str(e)}
