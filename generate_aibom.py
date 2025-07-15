import json  
import os  
import importlib.metadata  
import subprocess  
import hashlib  
import sys
sys.stdout.reconfigure(encoding='utf-8')

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--model-path", required=True, help="Path to the model directory")
args = parser.parse_args()
if not args.model_path:
    print("❌ Error: LOCAL_PATH is not set. Please provide it in the pipeline.")
    exit(1)
model_path = args.model_path
print(f"✅ Using model path: {model_path}")


# Get local_path from environment variables (pipeline parameters)
local_path = os.getenv("MODEL_DIR")

if not local_path:
    print("❌ Error: LOCAL_PATH is not set. Please provide it in the pipeline.")
    exit(1)

# def install_syft():  
  #  """Installs Syft if not already installed."""  
   # try:  
       # subprocess.run(["syft", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
       # print("✅ Syft is already installed.")  
    # except subprocess.CalledProcessError:  
       # print("⚙️ Installing Syft...")  
       # subprocess.run(["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/syft/main/install.sh", "|", "sh", "-s", "--", "-b", "/usr/local/bin"], check=True)  
       # print("✅ Syft installed successfully!")  

def calculate_file_hash(file_path):  
    if not os.path.exists(file_path):  
        return "N/A"  
    hasher = hashlib.sha256()  
    with open(file_path, "rb") as f:  
        hasher.update(f.read())  
    return hasher.hexdigest()  

def read_requirements(file_path):  
    if os.path.exists(file_path):  
        with open(file_path, "r") as f:  
            packages = [line.strip() for line in f.readlines() if line.strip()]  
        return {pkg: importlib.metadata.version(pkg) for pkg in packages if pkg in {d.metadata["Name"].lower() for d in importlib.metadata.distributions()}}  
    return {}  

def read_json(file_path):  
    if os.path.exists(file_path):  
        with open(file_path, "r") as f:  
            return json.load(f)  
    return {}  

def extract_model_metadata(model_file):  
    return {  
        "File Path": model_file,  
        "Size (KB)": os.path.getsize(model_file) / 1024 if os.path.exists(model_file) else "N/A",  
        "SHA-256 Hash": calculate_file_hash(model_file)  
    }  

def generate_aibom(input_folder, reports_folder):  
    """Generate AIBOM.json inside the reports folder."""  
    requirements_file = os.path.join(input_folder, "requirements.txt")  
    model_info_file = os.path.join(input_folder, "model_info.json")  
    dataset_file = os.path.join(input_folder, "dataset.json")  
    model_file = os.path.join(input_folder, "model.py")  

    aibom = {  
        "Model Information": read_json(model_info_file),  
        "Dataset Information": read_json(dataset_file),  
        "Dependencies": read_requirements(requirements_file),  
        "Model Metadata": extract_model_metadata(model_file),  
    }  

    aibom_file = os.path.join(reports_folder, "aibom.json")  
    with open(aibom_file, "w", encoding="utf-8") as f:  
        json.dump(aibom, f, indent=2)  

    print(f"✅ AIBOM saved to {aibom_file}")  
    return aibom_file  

def generate_sbom(input_folder, reports_folder):  
    """Generate SBOM using Syft and save it inside the reports folder."""  
    sbom_file = os.path.join(reports_folder, "sbom.json")  

    try:  
        subprocess.run(["syft", f"dir:{input_folder}","-o","spdx-json","-q"], check=True, stdout=open(sbom_file, "w"))  
        print(f"✅ SBOM saved to {sbom_file}")  
        return sbom_file  
    except subprocess.CalledProcessError as e:  
        print(f"❌ Error generating SBOM: {e}")  
        return None  

def generate_vulnerability_report(input_folder, reports_folder):  
    """Generate a vulnerability scan report using Trivy and save it inside the reports folder."""  
    vulnerability_file = os.path.join(reports_folder, "vulnerability.json") 
    sbom_path = os.path.join(reports_folder, "sbom.json")
    sbom_vulnereability_file = os.path.join(reports_folder, "sbom_vulnereability.json")

    cmd = ['trivy', 'sbom', '--format', 'json', 'sbom_path']
    try:  
        subprocess.run(["trivy", "fs", input_folder, "--include-dev-deps", "-f", "json", "-o", vulnerability_file], check=True)  
        print(f"✅ Vulnerability report saved to {vulnerability_file}")  
        
    except subprocess.CalledProcessError as e:  
        print(f"❌ Error generating vulnerability report: {e}")  
        return None  
        
    try:
        result = subprocess.run(["trivy", "sbom", sbom_path, "-f", "json", "-o", sbom_vulnereability_file],check=True,capture_output=True,text=True)
        print(f"✅ SBOM vulnerability report saved to {sbom_vulnereability_file}")
    except subprocess.CalledProcessError as e:
        print("❌ Trivy SBOM failed:")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        print("Return code:", e.returncode)
        return None

def load_vulnerabilities(file_path):
    with open(file_path) as f:
        data = json.load(f)
    vulnerabilities = set()
    full_vulns = {}

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln["VulnerabilityID"]
            vulnerabilities.add(vid)
            if vid not in full_vulns:
                full_vulns[vid] = vuln  # Save full vuln object

    return vulnerabilities, full_vulns

def compare_and_combine(file1, file2, output_file):
    vulns1, full_data1 = load_vulnerabilities(file1)
    vulns2, full_data2 = load_vulnerabilities(file2)

    if vulns1 == vulns2:
        print("✅ Both reports contain the same vulnerabilities.")
        combined = list(full_data1.values())  # No need to merge
    else:
        print("❗ Reports are different. Creating a combined output...")
        # Merge both dictionaries
        combined_dict = {**full_data1, **full_data2}
        combined = list(combined_dict.values())

        # Write to output JSON file
        with open(output_file, "w") as f:
            json.dump(combined, f, indent=2)
        print(f"✅ Combined vulnerabilities saved to: {output_file}")


def main():  
    """  
    Run full pipeline:  
    1. Install Syft  
    2. Generate AIBOM  
    3. Generate SBOM using Syft  
    4. Generate Vulnerability Report using Trivy  
    """  

    if not os.path.exists(local_path):  
        print(f"❌ Error: Model directory does not exist - {local_path}")  
        return  

    # Create reports folder  
    reports_folder = os.path.join(local_path, "reports")  
    os.makedirs(reports_folder, exist_ok=True)  

    # Install Syft before generating SBOM  
    # install_syft()  

    # Generate AIBOM  
    generate_aibom(local_path, reports_folder)  

    # Generate SBOM  
    generate_sbom(local_path, reports_folder)  

    # Generate Vulnerability Report  
    generate_vulnerability_report(local_path, reports_folder)  

    file1 = os.path.join(reports_folder, "vulnerability.json") 
    file2 = os.path.join(reports_folder, "sbom_vulnereability.json")
    output = os.path.join(reports_folder,"combined_vulnerabilities.json")

    compare_and_combine(file1, file2, output)

if __name__ == "__main__":  
    main()
