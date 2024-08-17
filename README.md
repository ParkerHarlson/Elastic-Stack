# Elastic Stack: Advanced Threat Detection and Response

This project showcases my ability to deploy and manage complex cybersecurity environments, simulate advanced attack scenarios, and configure sophisticated detection mechanisms using Elastic Stack. My work with tools like Zeek, Sysmon, and PowerShell, combined with a strong focus on log analysis and alerting, highlights my preparedness to address real-world security challenges in a professional setting.


**1. Set Up and Managed Virtual Environments**:
  - Configured three virtual machines:
    - **Ubuntu Box**: Installed and configured Zeek for network security monitoring.
    - **Windows Victim Box**: Used to generate logs and serve as the target for simulated attacks.
    - **Kali Box**: Deployed to conduct offensive security operations against the Windows machine.

    ![alt text](<Images/1.VM Setup.png>)

**2. Network Security Monitoring with Zeek**:
  - Installed and configured Zeek on the Ubuntu system to monitor network traffic and analyze logs for suspicious activities.

  ![alt text](Images/2.Zeek-Setup.png)

**3. Log Management and Analysis with Elastic**:
  - Integrated various agents into Elastic to centralize log collection, management, and analysis, ensuring comprehensive visibility into the network environment.

  ![alt text](Images/4.Zeek-Logs-Query.png)
  ![alt text](Images/3.Zeek-Setup-Logs.png)

**4. Malware Testing and Alert Generation**:
  - Downloaded and deployed WildFire malware to simulate a real-world threat scenario, generating alerts within Elastic. This process demonstrated the capability of Elastic SIEM in detecting and responding to malicious activities.

  ![alt text](Images/5.Wildfire-Test-Malware.png)
  ![alt text](Images/6.1Elastic-Alerts-Wildfire-Malware.png)
  ![alt text](Images/6.2Elastic-Alerts-Wildfire-Malware-Query.png)
  ![alt text](Images/6.Elastic-Alerts-Wildfire-Malware-Details.png)

**5. Data Querying and Analysis**:
  - Leveraged Elastic's query language to analyze security alerts and logs, focusing on identifying potential threats and anomalies within the environment.

  ![alt text](Images/7.PowershellCommands.png)
  ![alt text](Images/7.1Query-Powershell-Commands.png)

**6. Enhanced Security Visibility with Sysmon**:
  - Implemented Sysmon on the Windows system to capture detailed system activity logs, significantly improving visibility into PowerShell activity and other critical system events.

  ![alt text](Images/8.Install-Configue-Sysmon.png)
  ![alt text](Images/8.1Sysmon-Elastic.png)
  ![alt text](Images/8.2Sysmon-Elastic-Query.png)

**7. PowerShell Command Visibility Enhancement**:
  - Executed PowerShell commands to query and analyze results, ensuring a robust security posture.
  - Modified Windows Group Policy settings to further enhance the logging and visibility of PowerShell commands, contributing to more effective threat detection and investigation.

  ![alt text](Images/9.Group-Policy-PowerShell.png)
  ![alt text](Images/9.1Command-Line-Visibility.png)

## Attack Scenarios

### 8. Attack Scenario 1: Web Server Exploitation
- Simulated an attack on a Python-based web server using tools like Nmap, Nikto, and OWASP ZAP.
- Developed and implemented custom query alerts within Elastic to detect the attack patterns, setting thresholds and triggers based on the MITRE ATT&CK framework.
- Successfully detected, triggered, and reviewed alerts in Elastic, validating the effectiveness of the monitoring setup.

![alt text](Images/10.Web-Server.png)
![alt text](Images/10.1Web-Server-Kali.png)
![alt text](Images/10.2Web-Server-Elastic.png)
![alt text](Images/11.Nikto-Scan.png)
![alt text](Images/11.Nmap-Scan.png)
![alt text](Images/11.OWASP-ZAP-Scan.png)
![alt text](Images/12.CustomQuerty.png)
![alt text](Images/12.4Alert-Triggered.png)

### 9. Attack Scenario 2: Reverse Shell Exploitation
- Created a reverse shell payload using Msfvenom, served through a Python HTTP server on Parrot OS.
- Crafted and executed a PowerShell script within a batch file on the Windows victim box to pull and execute the reverse shell, gaining access and validating the attack.
- Developed detection rules in Elastic to:
  - Identify batch files in HTTP traffic on unusual ports.
  - Detect PowerShell executions initiated by batch files.
  - Monitor for PowerShell Invoke-WebRequest actions downloading batch files.
  - Recognize potential Msfvenom payload executions.
-Executed the same attack scenarios from before, confirming the robustness of the detection rules as the alerts were successfully triggered and logged.

![alt text](Images/13.1MSFVenom-Payload.png)
![alt text](Images/13.2BatShell.png)
![alt text](Images/13.3Reverse-Shell.png)
![alt text](Images/13.4Elastic-Logs-Query.png)
![alt text](Images/14.0Alert-Bat-Files-HTTP.png)
![alt text](Images/14.1Alert-PowerShell-Execution-Bat.png)
![alt text](<Images/14.2PowerShell Invoke-WebRequest-Bat-Download.png>)
![alt text](Images/14.3Alert-MSFvenom.png)
![alt text](Images/15.1Alerts-Triggered.png)
![alt text](Images/15.2Alert-Triggered-Details.png)

