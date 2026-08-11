# Splunk Brute-Force Detection & Investigation Lab

## Overview

In this project, I built an end-to-end SOC detection and investigation workflow using Splunk Enterprise, Windows 11, and Kali Linux.

I simulated repeated failed SMB authentication attempts from Kali Linux against a Windows system and used Splunk to analyze the resulting Windows Security logs. I then created an SPL detection rule for repeated failed logins, configured a scheduled alert, and investigated the activity to determine whether any authentication attempts were successful.

The investigation identified repeated Windows Event ID 4625 failed logon events originating from the Kali system. I also reviewed the associated Windows authentication failure codes and searched for Event ID 4624 successful logons to determine whether the simulated attack resulted in successful authentication.

The activity was ultimately classified as a **true-positive, unsuccessful brute-force attempt**.

---

## Lab Environment

The lab consisted of the following systems:

| System | Purpose |
|---|---|
| Kali Linux | Simulated attacker and generated authentication attempts |
| Windows 11 | Target system and source of Windows Security events |
| Splunk Enterprise | SIEM used for log analysis, detection, alerting, and investigation |
| VirtualBox | Virtualized lab environment |

### Lab Workflow

```text
Kali Linux
    |
    | SMB Authentication Attempts
    v
Windows 11
    |
    | Windows Security Events
    v
Splunk Enterprise
    |
    +--> Detection
    +--> Alert
    +--> Investigation
    +--> Analyst Conclusion
```

---

## Project Objectives

The objectives of this project were to:

- Generate controlled suspicious authentication activity in a home lab.
- Observe how failed Windows authentication attempts appear in security logs.
- Use Splunk Search Processing Language (SPL) to analyze authentication events.
- Develop a detection for repeated failed authentication attempts.
- Configure a Splunk alert based on the detection.
- Investigate the source, targeted account, and authentication results.
- Determine whether the activity resulted in successful authentication.
- Analyze Windows authentication failure codes.
- Document the findings using a basic SOC investigation workflow.

---

## 1. Testing SMB Connectivity

Before generating the authentication activity, I verified that SMB was accessible on the Windows target.

From Kali Linux, I scanned TCP port 445 using Nmap:

```bash
nmap -Pn -p 445 10.0.1.2
```

The scan showed:

```text
PORT    STATE SERVICE
445/tcp open  microsoft-ds
```

This confirmed that the Windows system was reachable over SMB.

I also verified that `smbclient` was installed:

```bash
which smbclient
```

I then performed a single controlled authentication attempt against the Windows system using the lab account.

The attempt returned:

```text
NT_STATUS_LOGON_FAILURE
```

This established that the test generated the expected failed authentication activity before moving on to repeated attempts.

### Screenshot

![SMB Connectivity Test](screenshots/01-smb-connectivity-test.png)

---

## 2. Simulating Repeated Failed Authentication Attempts

After confirming connectivity, I generated multiple failed authentication attempts from the Kali Linux system.

A simple Bash loop was used to repeat the SMB authentication attempt:

```bash
for i in {1..10}; do smbclient -L //10.0.1.2 -U 'SOCtest%WrongPassword123'; done
```

The attempts repeatedly returned:

```text
session setup failed: NT_STATUS_LOGON_FAILURE
```

This provided a controlled simulation of repeated password-guessing behavior within the isolated lab environment.

### Screenshot

![Repeated Failed Authentication Attempts](screenshots/02-repeated-failed-logins.png)

---

## 3. Identifying Failed Logons in Splunk

After generating the authentication attempts, I searched the Windows Security logs in Splunk for:

**Event ID 4625 — An account failed to log on**

The search identified the simulated activity and allowed me to extract important fields including:

- Target username
- Source IP address
- Workstation name
- Timestamp

Example SPL:

```spl
index=* source="XmlWinEventLog:Security" EventCode=4625
TargetUserName="SOCtest" IpAddress="10.0.3.11"
| table _time TargetUserName IpAddress WorkstationName
| sort _time
```

The results identified:

```text
TargetUserName:  SOCtest
IpAddress:       10.0.3.11
WorkstationName: KALI
EventCode:       4625
```

The timestamps also showed multiple authentication failures occurring only seconds apart.

### Screenshot

![Windows Failed Logons in Splunk](screenshots/03-event-4625-failed-logins.png)

---

## 4. Creating the Brute-Force Detection

Rather than manually reviewing individual authentication failures, I created an SPL search designed to identify repeated failed authentication attempts.

```spl
index=* source="XmlWinEventLog:Security" EventCode=4625
| stats count by TargetUserName IpAddress WorkstationName
| where count >= 5
```

### Detection Logic

The search:

1. Searches Windows Security events.
2. Filters for Event ID `4625`.
3. Groups the events by target username, source IP address, and workstation.
4. Counts the number of failed authentication attempts.
5. Returns results when the count reaches or exceeds five attempts.

During testing, the detection identified:

```text
TargetUserName:  SOCtest
IpAddress:       10.0.3.11
WorkstationName: KALI
Count:           21
```

This transformed the raw authentication telemetry into actionable detection logic.

### Screenshot

![Brute Force SPL Detection](screenshots/04-brute-force-detection.png)

---

## 5. Configuring a Splunk Alert

I saved the detection as a Splunk alert named:

**Brute Force Login Detection**

The alert was configured as a scheduled detection that runs hourly.

### Trigger Condition

```text
Number of Results > 0
```

The SPL search already requires at least five failed authentication attempts before returning a result. Therefore, any result returned by the search satisfies the detection threshold.

The alert was configured with:

```text
Alert Type:      Scheduled
Schedule:        Hourly
Trigger:         Number of Results > 0
Severity:        Medium
Action:          Add to Triggered Alerts
Status:          Enabled
```

This allowed the detection logic to operate automatically rather than requiring an analyst to manually run the search.

### Screenshot

![Splunk Brute Force Alert](screenshots/05-splunk-alert.png)

---

## 6. Investigating the Detection

After identifying the repeated authentication failures, I investigated whether the activity resulted in a successful authentication.

Windows uses:

```text
4625 = Failed logon
4624 = Successful logon
```

I searched for both event types associated with the targeted account:

```spl
index=* source="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624)
TargetUserName="SOCtest"
| table _time EventCode TargetUserName IpAddress WorkstationName
| sort _time
```

The investigation returned the repeated `4625` events but did not identify a corresponding `4624` successful authentication for the targeted account during the investigated period.

This indicated that the simulated password-guessing activity did not result in successful authentication.

---

## 7. Analyzing Authentication Failure Codes

I then examined additional fields within the Event ID 4625 events to determine why Windows rejected the authentication attempts.

```spl
index=* source="XmlWinEventLog:Security" EventCode=4625 TargetUserName="SOCtest"
| table _time TargetUserName IpAddress WorkstationName FailureReason Status SubStatus
| sort _time
```

The events consistently contained:

```text
FailureReason: %%2313
Status:        0xC000006D
SubStatus:     0xC0000064
```

The status information indicated a failed authentication attempt, while the substatus indicated that the specified username did not exist on the target system.

This provided additional context beyond simply identifying that authentication had failed.

### Screenshot

![Windows Authentication Failure Analysis](screenshots/06-authentication-failure-analysis.png)

---

## Investigation Findings

The investigation established the following:

| Finding | Result |
|---|---|
| Activity | Repeated failed SMB authentication attempts |
| Target Account | SOCtest |
| Source IP | 10.0.3.11 |
| Source Workstation | KALI |
| Failed Logon Event | Windows Event ID 4625 |
| Failed Attempts Observed | 21 |
| Successful Logon Observed | No |
| Status | 0xC000006D |
| SubStatus | 0xC0000064 |
| Detection Threshold | 5 or more failed attempts |
| Alert Severity | Medium |

---

## Analyst Assessment

The observed activity was consistent with a brute-force/password-guessing attempt against the `SOCtest` account.

Multiple failed authentication attempts originated from the same source system within a short period of time. The behavior exceeded the configured detection threshold and generated a result from the brute-force detection logic.

Further investigation did not identify a successful Event ID 4624 authentication for the targeted account during the investigated period.

The Windows authentication failure information also indicated that the authentication attempts were unsuccessful.

### Disposition

**True Positive — Unsuccessful Brute-Force Attempt**

No successful authentication or evidence of account compromise was identified during the investigation.

In a production SOC environment, additional investigation could include reviewing other activity associated with the source IP, examining the targeted endpoint for additional indicators, validating whether the source system is authorized, and escalating or containing the activity according to organizational incident-response procedures.

---

## Skills Practiced

This project provided hands-on practice with:

- Splunk Enterprise
- Splunk Search Processing Language (SPL)
- SIEM investigation
- Windows Security Event Logs
- Windows Event IDs 4624 and 4625
- Authentication log analysis
- Detection engineering fundamentals
- Threshold-based detection
- Splunk alert configuration
- Source IP and account investigation
- Windows authentication status codes
- Kali Linux
- Nmap
- SMB / `smbclient`
- Basic Bash loops
- SOC alert triage
- Incident documentation

---

## Key Takeaways

This project demonstrated the complete flow between attacker activity, endpoint telemetry, SIEM detection, and analyst investigation.

Rather than stopping after generating logs or locating Event ID 4625, I built detection logic that grouped repeated authentication failures and applied a threshold to identify suspicious behavior.

I then converted that detection into a scheduled Splunk alert and investigated the resulting activity to determine:

- Which account was targeted
- Where the authentication attempts originated
- How frequently the attempts occurred
- Why the authentication attempts failed
- Whether a successful authentication followed the failures

This reinforced how a SOC analyst can move from raw security telemetry to a documented security finding.

---

## Ethical Use

All activity in this project was performed in an isolated personal lab environment using systems created specifically for cybersecurity training.

The authentication activity was intentionally generated for defensive security education, detection engineering, and SOC analysis practice.
