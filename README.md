# NetSleuth

**Cross-platform Network Status & Security Scanner**


![Screenshot_From_2025-05-15_02-42-17](https://github.com/user-attachments/assets/907707b9-d387-43c3-9a60-d195b972af2f)

---

## Overview

NetSentry is a lightweight Python tool designed to:

- Detect active network adapters and IP addresses  
- Ping a public host to verify internet connectivity  
- Scan common TCP ports on localhost for open services  
- Provide basic security tips based on scan results

---

## Features

- Works on Windows and Arch Linux (and other Unix-like OSes)  
- Simple, colored CLI interface using `colorama`  
- No external dependencies except `colorama`  
- Modular, easy to extend with new scans or checks  

---

## Installation

1. Clone or download this repository:

```bash
git clone https://github.com/yxdrew87/netsleuth.git
cd netsentry
pip install -r requirements.txt
python main.py
