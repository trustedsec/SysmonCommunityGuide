Process Access
==============

When one process opens another, sysmon will log this with an event ID of 10. The access with higher permissions allows for also reading the content of memory, patching memory, process hollowing, creations of threads and other tasks that are abused by attackers. This technique has been used for access to credentials, keys and data that are in the process memory.

This task is also common for benign processes that query information on another process, such as Task Manager, tasklist.exe and others, this requires that a baseline be established and filtered out at a SIEM level taking into consideration other factors like image fullpath, parent process and account used so as to prevent any whitelisted processes from being used as staging for attacks.

Sysmon generates this event using ObRegisterCallbacks leveraging its
driver. The main 2 filtering fields recommended are:

* **TargetImage** - File path of the executable being accessed by
    another process.

* **GrantedAccess** - The access flags (bitmask) associated with the
    process rights requested for the target process

As a minimum it is recommended to filter including critical processes,
as a minimum:

* C:\\Windows\\system32\\lsass.exe

* C:\\Windows\\system32\\csrss.exe

* C:\\Windows\\system32\\wininit.exe

* C:\\Windows\\system32\\winlogon.exe

* C:\\Windows\\system32\\services.exe

Check for masks of known tools for credential dumping, process injection
and process hollowing. Great care should be taken when setting masks
since Sysmon does a literal comparison of the mask string provided
against the one returned. It is not a bitwise operation, care should be
taken to track the proper combinations.

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

The PSGumshoe PowerShell module has a function for creating and parsing
mask strings.
<https://github.com/PSGumshoe/PSGumshoe/blob/sysmon_events/EventLog/Get-SysmonAccessMask.ps1>

The fields for the even are:

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

* **CallTrace**: Stack trace of where open process is called. Included
    is the DLL and the relative virtual address of the functions in the
    call stack right before the open process call

Example:

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

Some examples of actions from security tools like Mimikatz and their
access masks

  |Command                 |Sysmon 10                                           |Security 4663 Kernel Object
  |-----------------------|---------------------------------------------------|-----------------------------
  |lsadump::lsa /patch     |GrantedAccess 0x1438                                |AccessMask 0x10
  |lsadump::lsa /inject    |rantedAccess 0x143a                                |AccessMask 0x10
  |lsadump::trust /patch   |GrantedAccess 0x1438                                |AccessMask 0x10
  |misc:memssp             |GrantedAccess 0x1438                                |AccessMask 0x10
  |Procdump mimidump       |GrantedAccess 0x1fffff                              |AccessMask 0x10
  |Task Manage minidump    |GrantedAccess 0x1400, 0x1000, 0x1410 and 0x1fffff   |AccessMask 0x10
  |sekurlsa::\*            |GrantedAccess 0x1010                                |AccessMask 0x10
