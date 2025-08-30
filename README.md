# Sentinel-EDR

**Sentinel-EDR** is a lightweight, open-source **agent–server Endpoint Detection and Response (EDR) tool**.  
It allows security teams to deploy agents on endpoints, collect suspicious activity logs, and forward them to a central server.  
The server provides a **real-time dashboard** with severity-based color-coded alerts for quick and effective threat monitoring.

---

## 🚀 Features

- 🖥️ **Agent–Server Architecture**  
  Deploy agents across multiple endpoints and centralize logs in one dashboard.  

- 🔍 **Suspicious Activity Detection**  
  Detects common endpoint threats such as:  
  - Execution of scripts from untrusted folders (PowerShell, CMD, VBS).  
  - Modification or deletion of critical system files by non-admin accounts.  
  - Suspicious outbound network connections from apps like Microsoft Office or Adobe Reader.  
  - Creation of scheduled tasks or services by non-system processes.  

- 🎨 **Dashboard with Dark Mode**  
  A modern web-based dashboard with **dark mode UI** and **color-coded alerts** (Critical, High, Medium, Low).  

- 🔑 **API Key Authentication**  
  Agents authenticate with the server using a secure API key.  

- ⚡ **Lightweight & Easy to Deploy**  
  Written in pure Python (Flask + requests), no heavy dependencies.  

---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Sentinel-EDR.git
cd Sentinel-EDR
```

### 2. Requirements
```bash
# Make sure pip is updated
python3 -m pip install --upgrade pip

# Install server dependencies
pip install flask flask_cors

# Install agent dependencies
pip install psutil requests

sudo apt update && sudo apt install -y python3-venv python3-pip
python3 -m venv venv
source venv/bin/activate
```
- If error occurred make sure you’re using the venv, activate it first
```bash
source edr-env/bin/activate
pip install flask_cors
```
- If using apt instead
```bash
sudo apt install python3-flask-cors -y
```

## 📡 Usage

### 1. Start the Server
```bash
python3 server.py
```
**and just visit http://<local-host/IP>:8000**
### 2. Run the Agent
```bash
python3 agent.py --server http://<server-ip>:8000 --agent <machine-name> --key <api-key>
```
⚠️ ** make sure api key match with server-side script.**


---

## 🔧 Customization – Adding Your Own Detection Rules  

One of the strengths of **Sentinel-EDR** is flexibility.  
You can easily extend or modify the **suspicious activity detection rules** in the **agent script**.  

### 📌 Where are the rules defined?  
- Rules are stored inside the `rules` dictionary in **`agent.py`**.  
- Each rule has three key parts:  
  - **description** → human-readable explanation of the suspicious activity.  
  - **severity** → `Low`, `Medium`, `High`, or `Critical`.  
  - **condition** → Python logic that checks process names, file paths, or network activity.  

### 📝 Example Rule  
```python
rules = {
    "rule1": {
        "description": "Execution of PowerShell from Downloads folder",
        "severity": "High",
        "condition": lambda event: event["process"] == "powershell.exe" and "Downloads" in event["path"]
    },
    "rule2": {
        "description": "Suspicious outbound connection from Microsoft Word",
        "severity": "Critical",
        "condition": lambda event: event["process"] == "WINWORD.EXE" and event["destination_port"] not in [80, 443]
    }
}
```
### ✨ How to add your own rules

- Open agent.py in a text editor.
- Find the rules section.
- Copy an existing rule and adjust the logic (change process name, file path, or ports).
- Restart the agent with:
```bash
python3 agent.py --server http://<server-ip>:8000 --agent mypc --key <api-key>
```
- ✅ Your new rules will automatically take effect and trigger alerts on the server dashboard.
