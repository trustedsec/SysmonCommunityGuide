Process Termination
-------------------

Sysmon will log an **EventID 5** when a process terminates. While less critical than process creation events, process termination logging provides valuable context for investigations and can help detect specific attacker behaviors, particularly defensive evasion techniques.

Detection Value and Use Cases
------------------------------

Process termination events serve several important purposes in detection engineering:

**Timeline Analysis**: By correlating process creation (Event ID 1) with termination events, you can calculate how long a process ran. A process that executes for only milliseconds might indicate reconnaissance or automated attack tools. A process that runs for an unusually long time might indicate persistence or data exfiltration.

**Defensive Evasion Detection**: Attackers frequently terminate security tools to operate undetected. Monitoring for the termination of specific processes can alert you when:
* Antivirus or EDR agents are killed
* Logging services are stopped
* Backup processes are terminated (common before ransomware deployment)
* Windows Defender processes are stopped
* Sysmon itself is terminated

**Incident Investigation**: When investigating an incident, knowing when processes stopped running helps establish a timeline. This is particularly valuable when analyzing malware that runs briefly, deletes itself, and terminates.

**Anomaly Detection**: Unexpected termination of critical system processes or services can indicate system instability, crashes due to exploitation, or deliberate sabotage.

**MITRE ATT&CK Mapping**: Process termination is relevant for detecting:
* **T1562 - Impair Defenses**: Stopping or killing security tools
* **T1489 - Service Stop**: Terminating services before destructive actions
* **T1490 - Inhibit System Recovery**: Stopping backup or recovery services

Configuration Strategy
-----------------------

Unlike process creation, process termination is a **lower priority event type** for most environments. The volume is similar to process creation (every process that starts will eventually terminate), but the detection value is lower. This leads to three common configuration approaches:

**Approach 1 - Do Not Log (Common)**: Many organizations do not log process termination at all. If storage or SIEM licensing is constrained, this is often the first event type to be disabled. You can still conduct investigations using only process creation events; you simply lose some timeline precision.

**Approach 2 - Log Everything**: Some organizations log all process termination events to maintain complete process lifecycle visibility. This approach makes sense if:
* You have sufficient storage and SIEM capacity
* You frequently conduct detailed forensic investigations
* You want precise process duration calculations
* Compliance requirements demand complete audit trails

**Approach 3 - Targeted Includes (Recommended)**: Rather than logging all terminations or using exclusions, configure Sysmon to only log termination of security-relevant processes. This provides the detection value without the volume burden.

Recommended Targeted Include Configuration
-------------------------------------------

The most effective approach is to only log termination of processes that matter for security monitoring:

```xml
<RuleGroup name="" groupRelation="or">
  <ProcessTerminate onmatch="include">

    <!-- Security Tools - Detect defensive evasion -->
    <Rule name="SecurityToolTermination" groupRelation="or">
      <Image condition="contains">defender</Image>
      <Image condition="contains">avast</Image>
      <Image condition="contains">avg</Image>
      <Image condition="contains">norton</Image>
      <Image condition="contains">mcafee</Image>
      <Image condition="contains">sophos</Image>
      <Image condition="contains">crowdstrike</Image>
      <Image condition="contains">carbon</Image>
      <Image condition="end with">MsSense.exe</Image>
      <Image condition="end with">SysmonDrv.exe</Image>
    </Rule>

    <!-- Critical System Processes -->
    <Rule name="CriticalProcessTermination" groupRelation="or">
      <Image condition="end with">lsass.exe</Image>
      <Image condition="end with">csrss.exe</Image>
      <Image condition="end with">wininit.exe</Image>
    </Rule>

    <!-- Backup and Recovery Services -->
    <Rule name="BackupServiceTermination" groupRelation="or">
      <Image condition="contains">vss</Image>
      <Image condition="contains">backup</Image>
      <Image condition="contains">wbadmin</Image>
    </Rule>

    <!-- Logging Services -->
    <Rule name="LoggingServiceTermination" groupRelation="or">
      <Image condition="end with">EventLog.exe</Image>
      <Image condition="contains">splunk</Image>
      <Image condition="contains">elastic</Image>
    </Rule>

  </ProcessTerminate>
</RuleGroup>
```

This configuration only logs termination of processes that are security-relevant, dramatically reducing volume while maintaining detection capability for defensive evasion attempts.

What to Monitor For
-------------------

When reviewing process termination events, look for these suspicious patterns:

**Security Tool Termination**: Any termination of antivirus, EDR, or monitoring tools should be investigated. Legitimate updates or administrative actions should be rare and documented.

**Batch Terminations**: Multiple processes terminated in rapid succession by the same parent process, especially if terminating security tools or system services. This pattern is common in ransomware and wiper malware.

**Unusual Termination Methods**: Processes terminated by debugging tools, scripts, or command-line utilities like taskkill.exe when targeting security processes.

**Short-Lived Suspicious Processes**: When correlated with process creation, very short process lifetimes for reconnaissance tools, credential dumpers, or other attack tools that execute and immediately exit.

The process termination fields are:

* **RuleName** -- Rule name for which the event triggered.

* **UtcTime** - Time in UTC when event was created

* **ProcessGuid** - Process Guid of the process that terminated

* **ProcessId** - Process ID used by the OS to identify the process
    that terminated

* **Image** - File path of the executable of the process that
    terminated