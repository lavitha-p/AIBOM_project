# AIBOM_Project
An automated framework to generate AI Bill Of Materials(AIBOM)

AIBOM Generation Tool
Overview

The AIBOM (AI Bill of Materials) Generation Tool automates the process of generating:

AIBOM (AI Bill of Materials)

SBOM (Software Bill of Materials)

Vulnerability Report


This tool is designed to work with various AI models by allowing users to provide their own model directory. The script ensures flexibility by keeping model dependencies separate from the tool itself.


---

Installation

1. Install General Dependencies

The script requires some basic dependencies. Install them using:

pip install numpy pandas json5

2. Install Model-Specific Dependencies

Since different AI models have different requirements, users must install dependencies based on their chosen model:

For PyTorch-based models (e.g., GPT-2, BERT, LLaMA):

pip install torch transformers

For TensorFlow-based models:

pip install tensorflow

For other models:
Refer to the official documentation and install the required libraries.



---

Usage

Command to Run the Script

Execute the script by providing the model directory path:

python generate_aibom.py --model-path /path/to/your/model

Example

If the AI model is stored in /home/user/models/gpt-2, use:

python generate_aibom.py --model-path /home/user/models/gpt-2


---

Output

After successful execution, the script will generate three JSON reports inside a reports/ directory:

Handling Vulnerabilities

If the vulnerability_report.json contains vulnerabilities, a warning message will be displayed:

⚠️ Warning: Model not ready for production! ⚠️


---

Directory Structure

After running the script, the expected directory structure is:

/path/to/your/model/
│── reports/
│ ├── aibom.json
│ ├── sbom.json
│ ├── vulnerability_report.json
│── other_model_files/


---

License

This project is open-source. Feel free to use and contribute!


---

Notes:

This script does not include model-specific dependencies; users must install them separately.

Ensure that the provided model directory contains valid model files before running the script.
