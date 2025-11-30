File Delete
===========

Sysmon will log **EventID 23** for file deletions, providing critical visibility into file destruction activity. This event type not only logs deletions but also archives the deleted files, allowing defenders to recover and analyze tools, malware, and other artifacts that attackers create and then delete. This is a **moderate-to-high volume event type** that requires careful filtering to capture high-value deletions while avoiding noise from normal system operations.

Detection Value and Why It Matters
-----------------------------------

File deletion monitoring detects critical attack patterns that other event types cannot capture:

**Ransomware Detection**: Ransomware typically follows this pattern:
1. Create encrypted copy of original file
2. Delete the original unencrypted file
3. Repeat across thousands of files rapidly

Monitoring file deletions reveals this pattern before significant damage occurs. High volumes of file deletions in user directories within short time windows is one of the strongest ransomware indicators.

**Wiper Malware**: Destructive attacks that permanently delete files and system components to cause damage and cover tracks. File deletion events help detect wiper software used by nation-state actors and destructive attackers.

**Anti-Forensics**: Attackers delete tools, scripts, and other artifacts after use to remove evidence:
* Deleting droppers/stagers after payload execution
* Removing tools after completing objectives
* Cleaning up temporary files and scripts
* Deleting log files to hide activity

**Data Destruction**: Intentional deletion of backup files, database files, or critical system files as part of an attack.

**MITRE ATT&CK Mapping**:
* **T1485 - Data Destruction** - Wiper malware and destructive attacks
* **T1486 - Data Encrypted for Impact** - Ransomware encryption
* **T1488 - Disk Structure Wipe** - Destructive wiping attacks
* **T1070.004 - Indicator Removal on Host: File Deletion** - Anti-forensics
* **T1490 - Inhibit System Recovery** - Deleting backups and shadow copies

Volume Characteristics and Filtering Strategy
----------------------------------------------

File deletion volume varies dramatically by use case:
* **Unfiltered volume**: Extremely high - thousands to tens of thousands of events per day
* **Normal operations**: Applications, Windows Updates, browsers, and temp file cleanup generate constant deletion activity
* **Filtered volume**: Can be reduced to 100-500 high-value events per day with proper filtering

**Critical Consideration**: The event includes file archiving by default. This means deleted files are copied to the Sysmon archive directory before deletion. This provides immense forensic value but has storage implications:
* Archived files consume disk space in the archive directory
* High-volume deletions can fill disk space quickly
* You must monitor archive directory size and implement retention policies
* Consider using EventID 26 (File Delete Detected, without archiving) for high-volume, low-value deletions

**Recommended Filtering Approach**: Target specific file types and locations that matter for security:
* Executable files (.exe, .dll, .sys) in suspicious locations
* Script files (.ps1, .bat, .vbs, .js) anywhere
* Office documents with macros (.docm, .xlsm)
* Archive files (.zip, .rar, .7z) from temp directories
* Database and backup files
* Multiple deletions in rapid succession (SIEM-side detection)

How Sysmon Monitors File Deletions
-----------------------------------

Sysmon uses a minifilter driver to monitor file system activity. The minifilter monitors three I/O request packets (IRP):
* **IRP_MJ_CREATE** - File creation
* **IRP_MJ_CLEANUP** - Handle closure
* **IRP_MJ_WRITE** - File writes

When a file is marked for deletion, Sysmon intercepts this event and can archive the file before it's permanently removed.

![minifilter](./media/image36.png)

**Important Limitation**: Like all minifilter-based monitoring, if any security software with a lower altitude number (higher priority) blocks or modifies the file deletion, Sysmon may not observe or archive the file correctly.

Archive Directory Configuration
--------------------------------

The archive directory stores copies of deleted files, providing critical forensic evidence. Proper configuration is essential:

**Setting the Archive Directory:**
* Specified in XML configuration: `<ArchiveDirectory>folder_name</ArchiveDirectory>`
* Or via registry: Set **FilterArchiveDirectory** value under the driver registry key parameters
* Default location if not specified: `C:\Sysmon\`

**Version-Specific Behavior:**
* **Sysmon 11.0**: Requires `-a <folder name>` command-line parameter during install, otherwise uses default "Sysmon" folder even if XML specifies different name
* **Sysmon 11.1 and later**: The `-a` parameter was removed; archive directory must be specified in XML configuration or default is used

**Archive Directory Security:**
The archive directory is protected by SYSTEM ACL to prevent tampering:

```
PS C:\> (Get-Acl C:\Sysmon\).access

FileSystemRights  : FullControl
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None
```

To access archived files, use PsExec to spawn a SYSTEM-level shell:
```
PsExec.exe -sid cmd
```

**Archive Directory Management:**
* Monitor disk space consumption
* Implement retention policies (delete old archived files)
* Consider separate volume for archive directory on high-activity systems
* Regularly review archived files for malware and tools
* Hash archived executables and submit to threat intelligence platforms

What to Investigate
--------------------

When reviewing file deletion events, prioritize investigation of:

**1. High Volume of Deletions (Ransomware Indicator)**
* Many files deleted from user directories within minutes
* Deletions spanning multiple file types and folders
* Particularly suspicious: `.doc`, `.xls`, `.pdf`, database files
* Cross-reference with file creation events for encrypted file extensions (`.encrypted`, `.locked`, `.crypto`)

**2. Suspicious File Types Deleted**
* Executables (`.exe`, `.dll`) from temp directories or downloads
* PowerShell scripts (`.ps1`, `.psm1`) anywhere
* Batch files (`.bat`, `.cmd`)
* VBScript/JavaScript (`.vbs`, `.js`, `.jse`)
* Macro-enabled Office files (`.docm`, `.xlsm`, `.pptm`)

**3. Deletions from Suspicious Locations**
* `\Downloads\` - Tools downloaded and then deleted
* `\AppData\Local\Temp\` - Droppers deleting themselves
* `\AppData\Roaming\` - Persistence mechanisms removing artifacts
* `\Content.Outlook\` - Email attachments deleted after execution
* `\Windows\Temp\` - System-level temp file deletions (especially by non-system processes)

**4. Backup and Shadow Copy Deletions**
* Volume shadow copy deletions (attackers disabling recovery)
* Database backup file deletions (`.bak`, `.backup`)
* System state backups
* Usually performed via `vssadmin.exe` or `wmic.exe` (check Process Creation events)

**5. Deletions by Suspicious Processes**
* PowerShell, CMD, or scripting engines deleting files
* Processes from temp or download directories
* Recently created processes (staging malware)
* Office applications deleting executable files (macro-based attack cleanup)

**6. Timing Patterns**
* Deletions immediately after file creation (dropper behavior)
* Deletions during off-hours
* Deletions correlating with other suspicious activity (lateral movement, credential access)

Event Fields
------------

The file delete event fields are:

* **RuleName**: Name of rule that triggered the event
* **UtcTime**: Time in UTC when event was created
* **ProcessGuid**: Process GUID of the process that deleted the file
* **ProcessId**: Process ID used by the OS to identify the process that deleted the file
* **Image**: File path of the process that deleted the file
* **TargetFilename**: Name of the file that was deleted
* **Hashes**: Full hash of the file with the algorithms in the HashType field. This is also the filename of the archived file in the ArchiveDirectory
* **Archived**: States whether the archival action was successful (`true` or `false`)

Configuration Examples
-----------------------

**Example 1: Monitor High-Value File Types in Suspicious Locations**

This configuration focuses on executables, scripts, and office files in locations commonly used by attackers:

```xml
<Sysmon schemaversion="4.30">
    <ArchiveDirectory>SysmonArchive</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDelete onmatch="include">
                <!-- Target suspicious locations -->
                <Rule groupRelation="and">
                    <Rule groupRelation="or">
                        <TargetFilename condition="contains">\Downloads\</TargetFilename>
                        <TargetFilename condition="contains">\Content.Outlook\</TargetFilename>
                        <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
                        <TargetFilename condition="contains">\AppData\Roaming\</TargetFilename>
                        <TargetFilename condition="begin with">C:\Windows\Temp\</TargetFilename>
                    </Rule>
                    <!-- AND high-value file extensions -->
                    <TargetFilename condition="end with any">.exe;.dll;.ps1;.bat;.cmd;.vbs;.js;.jse;.hta;.msi</TargetFilename>
                </Rule>
            </FileDelete>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 2: Ransomware Detection - Monitor User Document Deletions**

This configuration detects mass deletion of user files, a primary ransomware indicator:

```xml
<Sysmon schemaversion="4.30">
    <ArchiveDirectory>SysmonArchive</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDelete onmatch="include">
                <!-- User directories -->
                <Rule groupRelation="and">
                    <TargetFilename condition="contains any">\Users\;\Documents\;\Desktop\;\Pictures\</TargetFilename>
                    <!-- Common document/data file extensions -->
                    <TargetFilename condition="end with any">.doc;.docx;.xls;.xlsx;.ppt;.pptx;.pdf;.txt;.jpg;.png;.zip</TargetFilename>
                </Rule>
            </FileDelete>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 3: Anti-Forensics Detection - Scripts and Tools**

Focus on deletions that suggest cleanup activity:

```xml
<Sysmon schemaversion="4.30">
    <ArchiveDirectory>SysmonArchive</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDelete onmatch="include">
                <!-- All script files anywhere -->
                <TargetFilename condition="end with">.ps1</TargetFilename>
                <TargetFilename condition="end with">.bat</TargetFilename>
                <TargetFilename condition="end with">.cmd</TargetFilename>
                <TargetFilename condition="end with">.vbs</TargetFilename>
                <TargetFilename condition="end with">.js</TargetFilename>

                <!-- Executables from non-Program Files locations -->
                <Rule groupRelation="and">
                    <TargetFilename condition="end with">.exe</TargetFilename>
                    <TargetFilename condition="not begin with">C:\Program Files</TargetFilename>
                    <TargetFilename condition="not begin with">C:\Windows\</TargetFilename>
                </Rule>
            </FileDelete>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 4: Comprehensive Approach with Exclusions**

Start broader and exclude known-good deletion patterns:

```xml
<Sysmon schemaversion="4.30">
    <ArchiveDirectory>SysmonArchive</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDelete onmatch="exclude">
                <!-- Exclude browser cache and temp files -->
                <TargetFilename condition="contains">\AppData\Local\Microsoft\Windows\Temporary Internet Files\</TargetFilename>
                <TargetFilename condition="contains">\AppData\Local\Google\Chrome\User Data\Default\Cache\</TargetFilename>
                <TargetFilename condition="contains">\AppData\Local\Mozilla\Firefox\Profiles\</TargetFilename>

                <!-- Exclude Windows Update cleanup -->
                <Image condition="is">C:\Windows\System32\usocoreworker.exe</Image>
                <Image condition="is">C:\Windows\System32\svchost.exe</Image>

                <!-- Exclude common file extensions with high noise -->
                <TargetFilename condition="end with any">.tmp;.log;.etl;.old</TargetFilename>
            </FileDelete>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

Important Security Advisory
----------------------------

**Critical Vulnerability in Sysmon 11.0, 11.1, and 12.0**: A code execution vulnerability exists in these versions where an attacker with local administrative privileges can leverage a bug in how Sysmon handles File Delete events in memory. This allows arbitrary kernel writes where attackers can execute code with kernel-level privileges.

**Vulnerable Driver SHA256 Hashes:**
* 35c67ac6cb0ade768ccf11999b9aaf016ab9ae92fb51865d73ec1f7907709dca
* d2ed01cce3e7502b1dd8be35abf95e6e8613c5733ee66e749b972542495743b8
* a86e063ac5214ebb7e691506a9f877d12b7958e071ecbae0f0723ae24e273a73
* c0640d0d9260689b1c6c63a60799e0c8e272067dcf86847c882980913694543a
* 2a5e73343a38e7b70a04f1b46e9a2dde7ca85f38a4fb2e51e92f252dad7034d4
* 98660006f0e923030c5c5c8187ad2fe1500f59d32fa4d3286da50709271d0d7f
* 7e1d7cfe0bdf5f17def755ae668c780dedb027164788b4bb246613e716688840

**Mitigation**: Update to Sysmon 13.0 or later immediately. Monitor for these driver hashes using EventID 6 (Driver Load) events and alert on any attempts to load vulnerable versions.

Relationship to EventID 26
---------------------------

Sysmon also provides **EventID 26 (File Delete Detected)** which logs file deletions **without archiving** the deleted files. Use EventID 26 instead of EventID 23 when:
* Deletion volume is very high and archiving would consume too much disk space
* File types are large (ISO images, archives) making archiving impractical
* You want to log deletions for detection but don't need file recovery capability

See the File Delete Detected chapter for EventID 26 configuration guidance.
