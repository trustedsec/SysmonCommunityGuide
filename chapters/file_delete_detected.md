File Delete Detected
====================

Sysmon will log **EventID 26** for file deletions **without archiving** the deleted files. This event type was added in Sysmon version 13.10 and provides the same detection visibility as EventID 23 (File Delete) but without the storage overhead of file archiving. This is ideal for high-volume deletion monitoring where file recovery isn't necessary or where deleted file sizes make archiving impractical.

Detection Value and Use Cases
------------------------------

EventID 26 provides the same detection value as EventID 23 (File Delete with Archiving):
* Ransomware detection through mass file deletion patterns
* Wiper malware and data destruction attacks
* Anti-forensics activity (attackers deleting tools and artifacts)
* Backup and shadow copy deletion monitoring

The key difference is operational rather than detection-focused: **no files are archived**, which means:
* Significantly reduced disk space consumption
* Suitable for very high-volume deletion monitoring
* No file recovery capability
* Useful for detection-only scenarios where you don't need to analyze deleted files

When to Use EventID 26 vs EventID 23
-------------------------------------

Use **EventID 26 (File Delete Detected, no archiving)** when:
* **High deletion volume**: Environments where archiving would generate gigabytes of data daily
* **Large file types**: Monitoring deletions of ISO images, archive files, or other large files that would fill the archive directory quickly
* **Detection-only goals**: You want to detect deletion patterns (ransomware, cleanup activity) but don't need to recover or analyze the deleted files
* **Storage constraints**: Limited disk space makes archiving impractical
* **Known false positives**: You've identified high-value deletion patterns that generate many false positives, but you still want detection visibility

Use **EventID 23 (File Delete with Archiving)** when:
* **Malware recovery**: You need to capture and analyze attacker tools and scripts that are deleted after execution
* **Forensic evidence**: File recovery capability is critical for incident response
* **Low volume**: Deletion volume is manageable and won't overwhelm storage
* **High-value targets**: Monitoring specific file types (executables, scripts) where file recovery is valuable

**Best Practice**: Use both event types together:
* EventID 23 for high-value, low-volume deletions (executables and scripts in suspicious locations)
* EventID 26 for broader coverage where archiving isn't needed (user documents for ransomware detection, large files)

How It Works
------------

EventID 26 uses the same minifilter driver mechanism as EventID 23. The minifilter monitors for file system I/O request packets (IRP):
* **IRP_MJ_CREATE** - File creation
* **IRP_MJ_CLEANUP** - Handle closure
* **IRP_MJ_WRITE** - File writes

When a file is marked for deletion, Sysmon logs the event but **skips the archival step**, making it much more performant for high-volume scenarios.

![minifilter](./media/image36.png)

**Important Limitation**: Like EventID 23, if any security software with a lower altitude number (higher priority in the driver stack) blocks or modifies the file deletion before Sysmon observes it, the event may not be logged.

Event Fields
------------

The file delete detected event fields are:

* **RuleName**: Name of rule that triggered the event
* **UtcTime**: Time in UTC when event was created
* **ProcessGuid**: Process GUID of the process that deleted the file
* **ProcessId**: Process ID used by the OS to identify the process that deleted the file
* **Image**: File path of the process that deleted the file
* **TargetFilename**: Name of the file that was deleted
* **Hashes**: Full hash of the file with the algorithms in the HashType field (same as EventID 23, but file is not saved to archive)

Note that the **Archived** field is not present in EventID 26, as no archiving occurs.

What to Investigate
--------------------

Investigation priorities are identical to EventID 23 (File Delete):

**1. High Volume of Deletions (Ransomware)**
* Many files deleted rapidly from user directories
* Deletions spanning multiple folders and file types
* Document file deletions (`.doc`, `.xls`, `.pdf`, etc.)

**2. Suspicious File Types Deleted**
* Executables, scripts, Office macros in any location
* Tools and utilities from temp directories

**3. Deletions from Suspicious Locations**
* Downloads, temp directories, user AppData folders
* Email attachment temporary storage

**4. Backup and Recovery Inhibition**
* Shadow copy deletions, backup file deletions
* Usually correlates with `vssadmin.exe` or `wmic.exe` process activity

**5. Deletions by Suspicious Processes**
* PowerShell, CMD, scripting engines
* Recently created or unsigned processes
* Office applications deleting executables

**6. Timing and Correlation**
* Deletions immediately after file creation
* Deletions during off-hours
* Correlation with other suspicious events

Configuration Examples
-----------------------

**Example 1: Ransomware Detection with EventID 26 (No Archiving)**

Monitor user document deletions without archiving to avoid storage overhead:

```xml
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDeleteDetected onmatch="include">
                <!-- User data directories -->
                <Rule groupRelation="and">
                    <TargetFilename condition="contains any">\Users\;\Documents\;\Desktop\;\Pictures\;\Downloads\</TargetFilename>
                    <!-- Common document and data file types -->
                    <TargetFilename condition="end with any">.doc;.docx;.xls;.xlsx;.ppt;.pptx;.pdf;.txt;.jpg;.png;.gif;.mp4;.avi</TargetFilename>
                </Rule>
            </FileDeleteDetected>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 2: Combined Approach - Use Both EventID 23 and 26**

Use EventID 23 for executables/scripts (archive for forensics) and EventID 26 for documents (detection only):

```xml
<Sysmon schemaversion="4.30">
    <ArchiveDirectory>SysmonArchive</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <!-- EventID 23: Archive executables and scripts -->
            <FileDelete onmatch="include">
                <TargetFilename condition="end with any">.exe;.dll;.ps1;.bat;.cmd;.vbs;.js;.hta</TargetFilename>
            </FileDelete>

            <!-- EventID 26: Detect document deletions without archiving -->
            <FileDeleteDetected onmatch="include">
                <Rule groupRelation="and">
                    <TargetFilename condition="contains">\Users\</TargetFilename>
                    <TargetFilename condition="end with any">.doc;.docx;.xls;.xlsx;.pdf;.zip;.rar</TargetFilename>
                </Rule>
            </FileDeleteDetected>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 3: Large File Deletion Monitoring (ISO, IMG, Archive Files)**

Monitor deletion of large files that would be impractical to archive:

```xml
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDeleteDetected onmatch="include">
                <!-- Large file types - detection only, no archiving -->
                <TargetFilename condition="end with any">.iso;.img;.vhd;.vhdx;.vmdk;.ova</TargetFilename>

                <!-- Large archives -->
                <TargetFilename condition="end with any">.zip;.rar;.7z;.tar;.gz</TargetFilename>
            </FileDeleteDetected>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 4: Exclusion-Based Approach for Broad Coverage**

Log most deletions but exclude known noisy patterns:

```xml
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileDeleteDetected onmatch="exclude">
                <!-- Exclude browser caches and temp files -->
                <TargetFilename condition="contains">\AppData\Local\Microsoft\Windows\Temporary Internet Files\</TargetFilename>
                <TargetFilename condition="contains">\AppData\Local\Google\Chrome\User Data\Default\Cache\</TargetFilename>
                <TargetFilename condition="contains">\AppData\Local\Mozilla\Firefox\Profiles\</TargetFilename>

                <!-- Exclude Windows and application temp files -->
                <TargetFilename condition="end with any">.tmp;.temp;.log;.etl;.bak~;.old</TargetFilename>

                <!-- Exclude known system cleanup processes -->
                <Image condition="is">C:\Windows\System32\usocoreworker.exe</Image>
                <Image condition="is">C:\Windows\System32\dism.exe</Image>
            </FileDeleteDetected>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

Performance and Storage Considerations
---------------------------------------

EventID 26 is specifically designed for scenarios where EventID 23's archiving would create operational challenges:

**Storage Savings:**
* No archive directory needed for EventID 26 monitoring
* Typical ransomware attack deleting 10,000 files: EventID 23 might archive 500MB-5GB, EventID 26 generates only log events (~2MB of event data)
* Large file deletions (ISOs, backups): Can save hundreds of gigabytes

**Performance:**
* EventID 26 has minimal performance overhead (just logging)
* EventID 23 requires file copy operations which can impact system performance during mass deletions
* On systems with high deletion rates, EventID 26 may be the only practical option

**Best Practice Strategy:**
1. Start with targeted EventID 23 rules for high-value, low-volume file types (executables, scripts)
2. Add broader EventID 26 rules for detection patterns (user documents, large files)
3. Monitor archive directory size if using EventID 23
4. Shift rules from EventID 23 to EventID 26 if archiving becomes impractical

MITRE ATT&CK Mapping
--------------------

EventID 26 helps detect the same techniques as EventID 23:
* **T1485 - Data Destruction** - Wiper malware and destructive attacks
* **T1486 - Data Encrypted for Impact** - Ransomware encryption
* **T1488 - Disk Structure Wipe** - Destructive wiping attacks
* **T1070.004 - Indicator Removal on Host: File Deletion** - Anti-forensics
* **T1490 - Inhibit System Recovery** - Deleting backups and shadow copies

The difference is operational (archiving vs no archiving) rather than detection capability.
