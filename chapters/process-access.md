Process Access
==============

When one process opens another and requests access to its memory space, Sysmon will log this with an **Event ID 10**. This event type is critical for detecting some of the most dangerous post-exploitation techniques used by attackers, including credential theft, process injection, and memory manipulation.

Detection Value and Use Cases
------------------------------

Process access monitoring is essential because many advanced attack techniques require reading or modifying another process's memory. Understanding when and how processes access each other provides visibility into:

**Credential Dumping**: The most common use case for process access monitoring is detecting attempts to steal credentials from memory. Attackers frequently target specific Windows processes that contain credentials in memory:
* **lsass.exe** (Local Security Authority Subsystem Service) - Contains authentication credentials and is the primary target for tools like Mimikatz
* **csrss.exe** (Client/Server Runtime Subsystem) - Can contain sensitive session information
* **winlogon.exe** - Handles user logon and may contain plaintext passwords briefly

**Process Injection**: Attackers inject malicious code into legitimate processes to evade detection and gain elevated privileges. This requires opening the target process with specific access rights to write to its memory and create threads.

**Process Hollowing**: A technique where an attacker creates a legitimate process in a suspended state, replaces its code with malicious code, and then resumes execution. This also requires specific process access rights to manipulate memory.

**Defense Evasion**: Accessing security tool processes to disable protections, manipulate their behavior, or terminate them.

**MITRE ATT&CK Mapping**: Process access events help detect:
* **T1003.001 - OS Credential Dumping: LSASS Memory** - Reading LSASS process memory to extract credentials
* **T1055 - Process Injection** - Injecting code into running processes
* **T1055.012 - Process Hollowing** - Replacing legitimate process code with malicious code
* **T1106 - Native API** - Using low-level APIs to access processes
* **T1134 - Access Token Manipulation** - Opening processes to steal or manipulate access tokens

Volume Characteristics
-----------------------

Process access can generate moderate to high volumes of events depending on configuration. Many legitimate processes routinely access other processes for benign purposes:
* Task Manager queries all running processes
* Monitoring tools read process information
* Management agents check process status
* Security software scans running processes

This is why process access monitoring uses a **targeted include approach** rather than exclusions. Instead of logging all process access and filtering out normal activity, you configure Sysmon to only log access to specific critical processes or access attempts using specific dangerous access rights.

Configuration Strategy: Targeted Includes
------------------------------------------

Unlike high-volume event types such as process creation where you use exclusions to filter out noise, process access monitoring works best with **targeted includes**. You explicitly specify which processes to monitor and which access rights to alert on. This approach provides several benefits:

**Focused Detection**: By only monitoring specific critical processes, you ensure every event logged is potentially significant.

**Manageable Volume**: Limiting monitoring to a handful of critical system processes keeps event volume low.

**Clear Intent**: When a process access event is generated, it is because something accessed a process you specifically decided to protect. This makes triage straightforward.

**Reduced False Positives**: While you will still see some benign access to critical processes, the volume is low enough that filtering can be done at the SIEM level using additional context like source process path, user account, or parent process.

Key Filtering Fields
---------------------

Sysmon generates this event using ObRegisterCallbacks leveraging its driver. The main two filtering fields recommended are:

* **TargetImage** - File path of the executable being accessed by another process. This is how you specify which processes to protect.

* **GrantedAccess** - The access flags (bitmask) associated with the process rights requested for the target process. This allows you to filter for specific dangerous access rights.

Critical Processes to Monitor
------------------------------

As a minimum, it is recommended to monitor these critical Windows processes:

* **C:\\Windows\\system32\\lsass.exe** - Primary target for credential theft. This should always be monitored.

* **C:\\Windows\\system32\\csrss.exe** - Client/Server Runtime Subsystem, can contain session credentials

* **C:\\Windows\\system32\\wininit.exe** - Windows initialization process

* **C:\\Windows\\system32\\winlogon.exe** - Handles interactive logon, may contain credentials temporarily

* **C:\\Windows\\system32\\services.exe** - Service Control Manager

You may also want to monitor:
* Your EDR or antivirus processes (to detect attempts to disable security tools)
* Backup agent processes (to detect ransomware attempting to terminate backup services)
* Domain controller specific processes if monitoring DCs

Understanding Access Masks
---------------------------

Access masks define what permissions are being requested when one process opens another. Different attack techniques require different access rights, so understanding these masks helps you identify what an attacker is attempting to do.

**Important**: Sysmon performs a literal string comparison of the GrantedAccess value, not a bitwise operation. The mask must match exactly as logged. Care should be taken to track the proper combinations and test your filters to ensure they trigger correctly.

|Access                               |  Mask       |
|--------------------------------------|------------
| PROCESS\_CREATE\_PROCESS               |0x0080|
| PROCESS\_CREATE\_THREAD                |0x0002|
| PROCESS\_DUP\_HANDLE                   |0x0040|
| PROCESS\_SET\_INFORMATION              |0x0200|
| PROCESS\_SET\_QUOTA                    |0x0100|
| PROCESS\_QUERY\_LIMITED\_INFORMATION   |0x1000|
| SYNCHRONIZE                            |0x00100000|
| PROCESS\_QUERY\_INFORMATION            |0x0400|
| PROCESS\_SUSPEND\_RESUME               |0x0800|
| PROCESS\_TERMINATE                     |0x0001|
| PROCESS\_VM\_OPERATION                 |0x0008|
| PROCESS\_VM\_READ                      |0x0010|
| PROCESS\_VM\_WRITE                     |0x0020|

**Common Attack Patterns and Their Access Masks:**

Different attack tools and techniques use specific combinations of access rights:

* **0x1010** (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION) - Commonly used by Mimikatz sekurlsa module to read LSASS memory
* **0x1F1FFF** or **0x1FFFFF** - PROCESS_ALL_ACCESS, requests all possible rights, often used by debugging tools like ProcDump
* **0x1438** or **0x143A** - Used by Mimikatz lsadump module for various credential dumping operations
* **0x0810** (PROCESS_VM_READ + PROCESS_SUSPEND_RESUME) - Can indicate credential dumping attempts
* **0x0820** (PROCESS_VM_WRITE + PROCESS_CREATE_THREAD) - Strong indicator of process injection
* **0x0800** (PROCESS_SUSPEND_RESUME) - May indicate process hollowing when combined with other memory operations

**Legitimate Access Patterns to Expect:**

You will see some benign process access even when monitoring critical processes:

* Task Manager and monitoring tools querying process information with low-privilege access masks
* Security software scanning processes with read access
* Windows services performing normal system operations
* Management agents checking process status

These can typically be filtered at the SIEM level by creating exclusions for known-good source processes (e.g., Task Manager at C:\\Windows\\System32\\taskmgr.exe accessing with 0x1400 or 0x1000).

**The PSGumshoe PowerShell module has a function for creating and parsing mask strings:**
<https://github.com/PSGumshoe/PSGumshoe/blob/sysmon_events/EventLog/Get-SysmonAccessMask.ps1>

Event Fields
------------

The fields for the event are:

* **RuleName**: Rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **SourceProcessGUID**: Process Guid of the source process that
    opened another process.

* **SourceProcessId**: Process ID used by the OS to identify the
    source process that opened another process.

* **SourceThreadId**: ID of the specific thread inside of the source
    process that opened another process

* **SourceImage**: File path of the source process that created a
    thread in another process

* **TargetProcessGUID**: Process Guid of the target process

* **TargetProcessId**: Process ID used by the OS to identify the
    target process

* **TargetImage**: File path of the executable of the target process

* **GrantedAccess**: The access flags (bitmask) associated with the
    process rights requested for the target process

* **CallTrace**: Stack trace of where open process is called. Included is the DLL and the relative virtual address of the functions in the call stack right before the open process call. This field is valuable for identifying the code path that led to the process access, which can help distinguish legitimate tools from malicious ones.

Configuration Example
---------------------

Below is an example configuration that implements targeted monitoring of critical processes:

```xml
<Sysmon schemaversion="4.22">
   <EventFiltering>
 <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Detect Access to LSASS-->
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess>0x1FFFFF</GrantedAccess>
         </Rule>
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess>0x1F1FFF</GrantedAccess>
         </Rule>
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess>0x1010</GrantedAccess>
         </Rule>
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess>0x143A</GrantedAccess>
         </Rule>

        <!--Dumping credentials from services or setting up a keylogger-->
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\csrss.exe</TargetImage> <!--Mitre T1098--> <!--Mitre T1075--> <!--Mitre T1003--><!-- depending on what you're running on your host, this might be noisy-->
          <GrantedAccess>0x1F1FFF</GrantedAccess>
         </Rule>
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\wininit.exe</TargetImage> <!--Mitre T1098--> <!--Mitre T1075--> <!--Mitre T1003--><!-- depending on what you're running on your host, this might be noisy-->
          <GrantedAccess>0x1F1FFF</GrantedAccess>
         </Rule>
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\winlogon.exe</TargetImage> <!--Mitre T1098--> <!--Mitre T1075--> <!--Mitre T1003--><!-- depending on what you're running on your host, this might be noisy-->
          <GrantedAccess>0x1F1FFF</GrantedAccess>
         </Rule>
         <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\services.exe</TargetImage> <!--Mitre T1098--> <!--Mitre T1075--> <!--Mitre T1003--><!-- depending on what you're running on your host, this might be noisy-->
          <GrantedAccess>0x1F1FFF</GrantedAccess>
         </Rule>
         <Rule groupRelation="or">
            <GrantedAccess name="technique_id=T1003,technique_name=Credential Dumping">0x0810</GrantedAccess>
         </Rule>

         <!-- Detect process hollowing-->
         <Rule groupRelation="or">
            <GrantedAccess name="technique_id=T1093,technique_name=Process Hollowing">0x0800</GrantedAccess>
            <GrantedAccess name="technique_id=T1093,technique_name=Process Hollowing">0x800</GrantedAccess>
         </Rule>
         <!-- Detect process process injection-->
         <Rule groupRelation="or">
            <GrantedAccess name="technique_id=T1055,technique_name=Process Injection">0x0820</GrantedAccess>
            <GrantedAccess name="technique_id=T1055,technique_name=Process Injection">0x820</GrantedAccess>
         </Rule>
      </ProcessAccess>
</RuleGroup>
</EventFiltering>
</Sysmon>
```

Detection and Response Guidance
--------------------------------

**Known Credential Dumping Tool Access Patterns:**

Below are examples of access masks generated by common credential theft tools:

  |Command/Tool            |Sysmon 10 GrantedAccess                             |Security 4663 Kernel Object AccessMask
  |-----------------------|---------------------------------------------------|-----------------------------
  |Mimikatz lsadump::lsa /patch |GrantedAccess 0x1438                          |AccessMask 0x10
  |Mimikatz lsadump::lsa /inject|GrantedAccess 0x143a                          |AccessMask 0x10
  |Mimikatz lsadump::trust /patch|GrantedAccess 0x1438                         |AccessMask 0x10
  |Mimikatz misc::memssp       |GrantedAccess 0x1438                              |AccessMask 0x10
  |Procdump (mini dump LSASS)  |GrantedAccess 0x1fffff                            |AccessMask 0x10
  |Task Manager (create dump)  |GrantedAccess 0x1400, 0x1000, 0x1410, 0x1fffff    |AccessMask 0x10
  |Mimikatz sekurlsa::\*       |GrantedAccess 0x1010                              |AccessMask 0x10

**Analyzing CallTrace for Suspicious Indicators:**

The CallTrace field is one of the most valuable indicators for distinguishing legitimate access from attacks. It shows the stack of function calls that led to the process being opened, including which DLLs were involved.

**Suspicious DLLs to Watch For:**

* **dbghelp.dll** - Microsoft debugging library commonly used by memory dumping tools. Frequently seen in LSASS credential dumping attacks, particularly in older versions of Windows. Also used against svchost.exe to extract RDP credentials from Terminal Services.

* **dbgcore.dll** - Windows debugging core library, similar usage to dbghelp.dll. Often indicates memory dumping activity against critical processes.

* **ntdll.dll with uncommon call patterns** - While ntdll.dll is present in legitimate operations, unusual call stacks or direct API usage can indicate process injection or memory manipulation.

* **Unknown or suspicious third-party DLLs** - DLLs loaded from unusual paths or without proper signatures.

**Examples of Malicious CallTrace Patterns:**

When attackers dump LSASS memory using tools like ProcDump, Mimikatz, or custom dumpers, you will often see:
```
CallTrace: C:\Windows\System32\dbghelp.dll+...
CallTrace: C:\Windows\System32\dbgcore.dll+...
```

Attacks targeting svchost.exe for RDP credential theft show similar patterns with these debugging DLLs.

**Legitimate vs. Malicious CallTrace:**

* **Legitimate**: Windows system processes accessing LSASS typically show call traces through expected Windows DLLs (kernel32.dll, kernelbase.dll) for routine operations
* **Suspicious**: Call traces showing dbghelp.dll or dbgcore.dll accessing LSASS or svchost, especially from user-initiated processes or unusual parent processes
* **High Risk**: Call traces from these debugging DLLs when the source process is running from temp directories, user downloads, or is a script-based tool (PowerShell, cmd.exe)

**What to Watch For:**

When reviewing process access events, prioritize investigation of:

1. **Unknown or Unexpected Processes Accessing LSASS or svchost**: Any process you do not recognize or that should not need access to these critical processes

2. **Suspicious Source Paths**: Processes accessing critical processes from:
   * Temp directories (C:\\Users\\*\\AppData\\Local\\Temp, C:\\Windows\\Temp)
   * User download directories
   * Unusual system paths (C:\\ProgramData\\*, C:\\Users\\Public\\*)
   * Network shares

3. **Debugging DLLs in CallTrace**: Any CallTrace showing dbghelp.dll or dbgcore.dll should be investigated, especially when accessing LSASS or svchost

4. **PowerShell or Command-Line Tools**: While legitimate in some enterprise environments, PowerShell or cmd.exe accessing LSASS often indicates attack tools

5. **High-Privilege Access Masks**: 0x1FFFFF (PROCESS_ALL_ACCESS) from non-debugging, non-administrative tools

6. **After-Hours Access**: Credential dumping during off-hours when administrative activity is less expected

7. **RDP Credential Theft Indicators**: Process access to svchost.exe (especially the one hosting TermService) with debugging DLLs in the CallTrace

**Reducing False Positives:**

Process access monitoring of critical processes will generate some benign events. Use these strategies to reduce noise:

1. **SIEM-Level Filtering**: Rather than excluding at Sysmon level, filter known-good source processes in your SIEM using the full source image path

2. **Baseline Normal Behavior**: Document which management or security tools in your environment legitimately access LSASS and create exclusions for those specific processes

3. **Use the CallTrace Field**: Legitimate Windows processes will show expected DLL call stacks. Suspicious access often shows unusual call traces or debugging-related DLLs

4. **Correlate with Other Events**: Cross-reference with process creation events to understand what spawned the accessing process

5. **Whitelist by Path and Hash**: For legitimate tools, whitelist using both the full image path and file hash to prevent attackers from masquerading

**Testing Your Configuration:**

Validate your process access monitoring by safely simulating attacks in a test environment:

* Use Mimikatz in a lab to verify you detect sekurlsa and lsadump commands
* Test legitimate administrative tools to understand their access patterns and CallTrace signatures
* Verify ProcDump and Task Manager dump creation generates alerts with expected CallTrace data
* Simulate RDP credential theft techniques against svchost to verify detection
* Ensure CallTrace data is being captured and review the DLLs involved

By properly configuring and monitoring process access events, you gain visibility into some of the most critical phases of an attack: credential theft and code injection. This event type, when properly tuned, provides high-fidelity detections with manageable false positive rates.
