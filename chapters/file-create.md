File Create
===========

Via its filter driver, Sysmon can log the creation of files and information on what process created the file using **EventID 11**. File creation monitoring provides valuable detection capabilities for malware delivery, persistence mechanisms, and attacker tool staging. However, this is a high-volume event type that requires careful configuration to balance detection value with system performance and storage costs.

Detection Value and Use Cases
------------------------------

File creation monitoring provides visibility into several critical attack phases:

**Initial Access and Delivery**: Attackers must write malicious files to disk. File creation events help detect:
* Weaponized documents dropped by email clients or browsers
* Malware payloads downloaded from the internet
* Exploitation frameworks writing files to disk
* Drive-by download artifacts

**Execution and Staging**: Before executing payloads, attackers often stage files. Monitoring detects:
* Script files (.ps1, .vbs, .js, .bat) created by Office applications (malicious macros)
* Executable files dropped into temporary directories
* Tools downloaded for later execution (Mimikatz, PsExec, etc.)
* Compilation artifacts from .NET execution (DotNetToJS technique)

**Persistence Mechanisms**: Many persistence techniques involve file creation:
* Startup folder files for automatic execution
* Scheduled task XML files
* WMI MOF files for WMI persistence
* DLL files placed for DLL hijacking

**Defense Evasion**: Attackers create files to evade detection:
* Log file deletion and recreation (clearing evidence)
* Configuration files for malware
* Staging areas in unusual locations

**Credential Access**: Some credential theft creates files:
* LSASS dump files (created by ProcDump, Task Manager, Mimikatz)
* SAM/SYSTEM/SECURITY hive exports
* NTDS.dit copies from domain controllers

**MITRE ATT&CK Mapping**: File creation events help detect:
* **T1105 - Ingress Tool Transfer**: Downloading additional attack tools
* **T1059 - Command and Scripting Interpreter**: Script file creation for execution
* **T1053 - Scheduled Task/Job**: Task XML file creation
* **T1036 - Masquerading**: Files with misleading names or extensions
* **T1003 - OS Credential Dumping**: LSASS dump file creation
* **T1027 - Obfuscated Files or Information**: Encoded/encrypted file staging
* **T1204 - User Execution**: Malicious files delivered for user interaction

Understanding Minifilter Loading Order
---------------------------------------

An important technical detail: **Sysmon cannot log files that are blocked before they are written to disk.**

Antivirus and EDR products use minifilter drivers that load at lower altitude numbers than Sysmon (meaning they process I/O operations first). If an AV/EDR minifilter detects a malicious file and blocks it from being written, Sysmon never sees the file creation and cannot log it.

This means Sysmon file creation events are most valuable for detecting:
* Files that bypass AV/EDR detection (zero-days, obfuscated payloads)
* Living-off-the-land techniques using legitimate tools
* Files created in locations AV might not monitor as aggressively
* Post-exploitation activity after initial compromise

Volume Challenges and Configuration Strategy
---------------------------------------------

File creation is a **high-volume event type**. Modern Windows systems create thousands of files per hour through normal operation:
* Application updates and installations
* Temporary files for application processing
* Log files and cache files
* Browser downloads and cached data
* Windows system maintenance and updates
* User document saves and modifications

**Two main configuration approaches:**

**Approach 1 - Targeted Includes (Recommended for Most)**
Monitor only specific file types, locations, or processes known to indicate malicious activity. This is the most practical approach for most environments.

**Approach 2 - Exclusion-Based with Aggressive Filtering**
Log most file creation but exclude high-volume benign locations. This requires significant SIEM capacity and careful baseline analysis. Only suitable for organizations with extensive SIEM infrastructure.

**Hybrid Approach**
Combine both: include specific suspicious file types while excluding specific high-volume benign locations.

![minifilter](./media/image36.png)

The file creation event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that created the file

* **ProcessId**: Process ID used by the OS to identify the process that created the file (child)

* **Image**: File path of the process that created the file

* **TargetFilename**: Name of the file that was created

* **CreationUtcTime**: File creation time

High-Value File Types and Locations to Monitor
------------------------------------------------

**Suspicious File Extensions** (commonly created by attacks):
* **Scripts**: .ps1, .vbs, .js, .jse, .bat, .cmd, .hta - Script files for execution
* **Macros**: .docm, .xlsm, .pptm - Office documents with macros
* **Executables**: .exe, .dll, .sys in unusual locations
* **Scheduled Tasks**: .xml in `C:\Windows\System32\Tasks\` or `C:\Windows\Tasks\`
* **Build Files**: .proj, .sln - MSBuild project files (T1127)
* **ClickOnce**: .application, .appref-ms - ClickOnce deployment files
* **Registry**: .reg - Registry import files
* **Dump Files**: .dmp, .mdmp - Memory dump files (LSASS dumps)
* **Archives**: .zip, .rar, .7z in temp directories (staging/exfiltration)

**Suspicious File Locations** (where attackers commonly stage files):
* **Temp Directories**: `C:\Windows\Temp\`, `C:\Users\*\AppData\Local\Temp\`
* **Public Directories**: `C:\Users\Public\`, `C:\ProgramData\`
* **Startup Folders**: `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
* **Recycle Bin**: Unusual file creation in recycle bin directories
* **Root Directories**: `C:\`, `C:\Windows\`, `C:\Program Files\` (unusual for normal apps)

**Suspicious File Creation Patterns**:
* Office applications creating script files (malicious macro execution)
* Browsers creating executables (drive-by downloads)
* System utilities (certutil.exe, bitsadmin.exe) creating files
* Processes creating files in startup folders or scheduled task directories

Configuration Examples
-----------------------

**Example 1: Targeted Includes for Script Files and Execution Artifacts**

```XML
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileCreate onmatch="include">
                <!-- Detect Dangerous File Type Creation -->
                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=T1170,technique_name=Mshta" condition="end with">.hta</TargetFilename>
                </Rule>

                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=T1064,technique_name=Scripting" condition="end with">.bat</TargetFilename> <!--Batch scripting-->
                    <TargetFilename condition="end with">.cmd</TargetFilename> <!--Batch scripting | Credit @ion-storm -->
                    <TargetFilename condition="end with">.ps1</TargetFilename> <!--PowerShell-->
                    <TargetFilename condition="end with">.ps2</TargetFilename> <!--PowerShell-->
                    <TargetFilename condition="end with">.jse</TargetFilename> <!--Registry File-->
                    <TargetFilename condition="end with">.vb</TargetFilename> <!--VisualBasicScripting files-->
                    <TargetFilename condition="end with">.vbe</TargetFilename> <!--VisualBasicScripting files-->
                    <TargetFilename condition="end with">.vbs</TargetFilename> <!--VisualBasicScripting files-->
                </Rule>

                <!-- Detect ClickOnce -->
                <Rule groupRelation="or">
                    <TargetFilename name="ClickOnce File Execution" condition="end with">.application</TargetFilename>        <TargetFilename condition="end with">.appref-ms</TargetFilename>
                </Rule>

                <!-- MSBuild -->
                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=T1127,technique_name=Trusted Developer Utilities" condition="end with">.*proj</TargetFilename><!--Microsoft:MSBuild:Script More information: https://twitter.com/subTee/status/885919612969394177-->
                    <TargetFilename condition="end with">.sln</TargetFilename>
                </Rule>

                <!-- Macro File Creation -->
                <Rule groupRelation="or">
                    <TargetFilename name="Microsoft:Office: Macro" condition="end with">.docm</TargetFilename>
                    <TargetFilename condition="end with">.pptm</TargetFilename>
                    <TargetFilename condition="end with">.xlsm</TargetFilename>
                    <TargetFilename condition="end with">.xlm</TargetFilename>
                    <TargetFilename condition="end with">.dotm</TargetFilename>
                    <TargetFilename condition="end with">.xltm</TargetFilename>
                    <TargetFilename condition="end with">.potm</TargetFilename>
                    <TargetFilename condition="end with">.ppsm</TargetFilename>
                    <TargetFilename condition="end with">.sldm</TargetFilename>
                    <TargetFilename condition="end with">.xlam</TargetFilename>
                    <TargetFilename condition="end with">.xla</TargetFilename>
                </Rule>

                <!-- DotNettoJS UsageLog -->
                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=1218,technique_name=DotnettoJs" condition="contains">AppData\Local\Microsoft\CLR_v2.0\UsageLogs\</TargetFilename><!--Dotnet v2 binary started-->
                    <TargetFilename condition="end with">\UsageLogs\cscript.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\wscript.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\wmic.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\mshta.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\svchost.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\regsvr32.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\rundll32.exe.log</TargetFilename>
                </Rule>
            </FileCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 2: Credential Dumping File Creation**

Monitor for memory dump files and credential theft artifacts:

```xml
<FileCreate onmatch="include">
  <!-- LSASS Dump Files -->
  <TargetFilename name="LsassDump" condition="end with">.dmp</TargetFilename>
  <TargetFilename condition="end with">.mdmp</TargetFilename>

  <!-- Registry Hive Exports (SAM/SYSTEM/SECURITY) -->
  <TargetFilename name="RegistryHiveExport" condition="contains">sam.save</TargetFilename>
  <TargetFilename condition="contains">system.save</TargetFilename>
  <TargetFilename condition="contains">security.save</TargetFilename>

  <!-- NTDS.dit Copies (Domain Controller) -->
  <TargetFilename condition="contains">ntds.dit</TargetFilename>
</FileCreate>
```

**Example 3: Executables in Suspicious Locations**

```xml
<FileCreate onmatch="include">
  <!-- Executables in Temp Directories -->
  <Rule name="ExeInTemp" groupRelation="and">
    <TargetFilename condition="contains">\Temp\</TargetFilename>
    <TargetFilename condition="end with">.exe</TargetFilename>
  </Rule>

  <!-- Executables in Public Directories -->
  <Rule groupRelation="and">
    <TargetFilename condition="contains">C:\Users\Public\</TargetFilename>
    <TargetFilename condition="end with">.exe</TargetFilename>
  </Rule>

  <!-- DLLs in Suspicious Locations -->
  <Rule groupRelation="and">
    <TargetFilename condition="contains">\AppData\</TargetFilename>
    <TargetFilename condition="end with">.dll</TargetFilename>
  </Rule>
</FileCreate>
```

**Example 4: Persistence Artifact Detection**

```xml
<FileCreate onmatch="include">
  <!-- Startup Folder Files -->
  <TargetFilename name="StartupPersistence" condition="contains">\Start Menu\Programs\Startup\</TargetFilename>

  <!-- Scheduled Task XML Files -->
  <TargetFilename name="ScheduledTaskCreation" condition="begin with">C:\Windows\System32\Tasks\</TargetFilename>
  <TargetFilename condition="begin with">C:\Windows\Tasks\</TargetFilename>
</FileCreate>
```

Common Exclusions for Exclusion-Based Approach
-----------------------------------------------

If using an exclusion-based strategy (log most, exclude benign high-volume), consider these exclusions. **Use with caution** and validate volume reduction:

```xml
<FileCreate onmatch="exclude">
  <!-- Windows Update and System Files -->
  <TargetFilename condition="begin with">C:\Windows\SoftwareDistribution\</TargetFilename>
  <TargetFilename condition="begin with">C:\Windows\WinSxS\</TargetFilename>
  <TargetFilename condition="begin with">C:\Windows\Prefetch\</TargetFilename>

  <!-- Browser Cache (High Volume) -->
  <TargetFilename condition="contains">\Google\Chrome\User Data\</TargetFilename>
  <TargetFilename condition="contains">\Mozilla\Firefox\Profiles\</TargetFilename>
  <TargetFilename condition="contains">\Microsoft\Edge\User Data\</TargetFilename>

  <!-- Application Logs and Caches -->
  <TargetFilename condition="contains">\AppData\Local\Microsoft\Windows\WebCache\</TargetFilename>
  <TargetFilename condition="contains">\AppData\Local\Microsoft\Windows\INetCache\</TargetFilename>
</FileCreate>
```

**Warning**: Never completely exclude:
* Executable files (.exe, .dll, .sys) from any location
* Script files (.ps1, .vbs, .bat, .js) from any location
* Scheduled task directories
* Startup folders

What to Investigate
-------------------

When reviewing file creation events, prioritize these patterns:

**1. Office Applications Creating Scripts**
* WINWORD.EXE, EXCEL.EXE, or POWERPNT.EXE creating .ps1, .vbs, .bat, or .js files
* Strong indicator of malicious macro execution
* Cross-reference with process creation events to see if the script was executed

**2. Browsers Creating Executables**
* chrome.exe, msedge.exe, or firefox.exe creating .exe or .dll files
* May indicate drive-by downloads or malicious file downloads
* Legitimate downloads typically go to Downloads folder with user interaction

**3. System Utilities Downloading Files**
* certutil.exe, bitsadmin.exe, or powershell.exe creating files (especially .exe)
* Common living-off-the-land technique for downloading attack tools

**4. Memory Dump File Creation**
* Any .dmp or .mdmp file creation, especially if not from legitimate debugging tools
* Check source process - is it ProcDump, Task Manager, or an unknown tool?
* Check file location - LSASS dumps in temp directories are highly suspicious

**5. Files in Startup or Scheduled Task Directories**
* Any file creation in startup folders or task directories
* Cross-reference with registry events for persistence detection
* Validate legitimacy of the creating process

**6. Executable Files in Uncommon Locations**
* .exe or .dll files in temp directories, ProgramData, or user profile directories
* Legitimate software installs to Program Files or ProgramData with installers
* Malware often stages in temp or user directories

**7. Archives in Temp Directories**
* .zip, .rar, or .7z files created in temp locations
* May indicate data staging for exfiltration
* Large files or multiple archives in sequence are particularly suspicious

**8. Unusual Process Creating Files**
* Processes running from temp directories creating files
* System processes creating files in unusual locations
* Unsigned processes creating executables or scripts

Performance Considerations
---------------------------

File creation monitoring can impact performance if misconfigured:

**Volume Management**:
* Targeted includes: Expect 100-1000 events/day/host
* Exclusion-based with aggressive filtering: May see 5000-10000 events/day/host
* Test configurations in lab before production deployment

**Performance Tips**:
* Avoid monitoring entire drives or broad wildcards
* Prefer specific file extensions and paths over broad patterns
* Consider disabling file creation monitoring on extremely high-I/O servers (databases, file servers)
* Use "end with" for extensions rather than "contains" when possible

**Typical Well-Configured Volume**:
* Workstations: 50-200 events/day
* Servers: 100-500 events/day
* Domain Controllers: 200-1000 events/day (higher due to replication)

Testing and Validation
-----------------------

Validate your file creation monitoring:

1. **Macro Test**: Create a test Excel file with macro that writes a .ps1 file
2. **Download Test**: Download a test executable via browser
3. **Credential Dump Simulation**: Use ProcDump on LSASS in lab to verify .dmp detection
4. **Persistence Test**: Create a file in startup folder
5. **Volume Baseline**: Monitor event volume for 1-2 weeks to establish normal patterns
6. **Performance Check**: Verify Sysmon is not consuming excessive CPU or I/O

File creation monitoring, when properly configured with targeted includes for high-value file types and locations, provides critical visibility into malware staging, persistence establishment, and credential theft. The key is balancing comprehensive coverage with manageable event volume through thoughtful selection of monitored file types and locations.
