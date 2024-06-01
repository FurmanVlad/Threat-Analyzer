# Threat Analyzer

The "Threat Analyzer" is a Python application designed to monitor network traffic and associate this traffic with running processes on a machine. This tool provides real-time insights into the network activities of various processes.

## Features
1. **View Running Processes On This Machine**
   - Allows users to retrieve information about the currently running processes on their local machine. It helps to monitor system health, identify suspicious activities, or troubleshoot issues.

2. **Check File Hashes Via Virus Total**
   - Verify the integrity and safety of your files by calculating their hash values and cross-referencing them with VirusTotal's database. Instantly get alerts if a file matches a known malicious hash.
   - The user can directly input a file hash or choose a file from the machine.

3. **Check IP On AbuseIPDB**

   - Query the AbuseIPDB service to assess whether an IP address has been reported for abusive behavior. Identify potentially malicious IP addresses to enhance your network security.

4. **Display DNS Info**
   - Obtain detailed DNS records for any domain or hostname, providing crucial information for network troubleshooting and security analysis.

5. **Network Monitoring**
   - Monitor network traffic, including all incoming and outgoing connections, to detect unusual or unauthorized activities. This feature helps in identifying potential security breaches and performance issues promptly.



## Installation

```bash
pip install virustotal-api
pip install psutil
pip install wmi
```
- In MainPanel.py, change the path of your folder that contains all of the .py files.
- To run: just run MainPanel.py.
