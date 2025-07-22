# SecurityAnalysis_Web-Shell-Attack-Investigation
# Web Shell Attack Investigation
# Description
This repository contains comprehensive documentation of a web shell attack investigation using PCAP analysis and threat intelligence. The investigation aims to identify the geographical origin of the attack, determine exploited vulnerabilities, and track malicious activities performed by the attacker.

# Investigation Objectives
1. Identify attacker's IP address and geographical location
2. Determine User-Agent used for creating robust filtering rules
3. Identify malicious web shell successfully uploaded
4. Locate file upload storage directory
5. Detect ports used for unauthorized outbound communication
6. Identify files targeted for exfiltration

# Analysis Methodology
1. Malicious IP Address Identification

  * Analysis of source and destination IP addresses in PCAP file
  * Filtering for HTTP GET requests: http.request.method == GET
  * Geo-IP lookup using services like https://ipgeolocation.io/

2. User-Agent Analysis

  * Examination of HTTP packets for User-Agent information
  * Extraction of User-Agent string from HTTP GET requests
  * Detected User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

3. Web Shell Upload Detection

  * Focus on HTTP POST requests for file uploads
  * Filter: http.request.method == POST
  * Follow HTTP stream to view upload details
  * Successfully uploaded malicious file: image.jpg.php

4. Upload Directory Identification

  * Tracking web shell script execution in HTTP POST requests
  * Filter: http.request.uri contains "<Uploaded_Filename>"
  * Upload directory: /reviews/uploads/

5. Outbound Communication Detection

  * Analysis of uploaded file for backdoor configuration
  * Follow HTTP stream to view file contents
  * Target communication port: [Port detected in TCP stream]

6. Data Exfiltration Identification

  * Search for exfiltration evidence in outbound traffic
  * Filter: tcp.dstport == <Detected_Port>
  * Follow TCP stream to identify files or commands
  * Look for curl -X POST commands in TCP stream

# Tools and Techniques
# Wireshark Filters Used
  http.request.method == GET
  http.request.method == POST
  http.request.uri contains "<filename>"
  tcp.dstport == <port_number>
  tcp.stream eq <stream_number>

# Analysis Steps
  1. Network Traffic Analysis: Using Wireshark for PCAP analysis
  2. HTTP Stream Following: Right-click packet → Follow → HTTP Stream
  3. TCP Stream Analysis: Using tcp.stream eq for detailed analysis
  4. Geo-IP Intelligence: Geographic location lookup of IP addresses
  5. Threat Intelligence: User-Agent and behavioral pattern analysis

# Key Findings
# Identified Artifacts

  * Malicious Web Shell: image.jpg.php
  * Upload Directory: /reviews/uploads/
  * User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

# Indicators of Compromise (IoCs)

  * Attacker's source IP address
  * Malicious file: image.jpg.php
  * Suspicious HTTP POST requests to upload directory
  * Outbound connections to specific ports
  * Data exfiltration attempts

# Attack Timeline

  * Initial Reconnaissance: HTTP GET requests from attacker's IP
  * File Upload Attempts: Multiple POST requests to upload endpoint
  * Successful Web Shell Upload: image.jpg.php uploaded to /reviews/uploads/
  * Web Shell Execution: POST requests targeting the uploaded shell
  * Outbound Communication: Establishment of backdoor connection
  * Data Exfiltration: Attempts to steal sensitive files

# Mitigation and Recommendations
# Immediate Actions

  * Geo-blocking: Implement blocking based on attacker's geographical location
  * File Removal: Delete malicious file from /reviews/uploads/ directory
  * Access Control: Restrict access to upload directory
  * User-Agent Filtering: Create rules to block identified User-Agent
  * Network Isolation: Block outbound connections to suspicious ports

# Long-term Security Measures

  * Input Validation: Implement strict file upload validation
  * Web Application Firewall: Deploy WAF with anti-webshell rules
  * File Upload Security:
        - Whitelist allowed file extensions
        - Scan uploaded files for malicious content
        - Isolate upload directories from web root
        - Implement file type validation beyond extension checking
  * Network Monitoring: Continuous monitoring for suspicious outbound connections
  * Incident Response Plan: Update procedures for web shell attack response
  * Security Awareness: Train developers on secure file upload practices

# MITRE ATT&CK Mapping

* T1190: Exploit Public-Facing Application
* T1505.003: Web Shell
* T1041: Exfiltration Over C2 Channel
* T1083: File and Directory Discovery
* T1027: Obfuscated Files or Information

Disclaimer
All analysis was performed in a controlled environment for defensive security purposes. This information should not be used for malicious purposes.

- Author: Michael Anggi Gilang Angkasa
- Last Updated: 22 July 2025
- Classification: TLP:WHITE
- Status: Investigation Complete
