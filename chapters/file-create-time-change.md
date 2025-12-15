File Create Time Change
=======================

Sysmon will log **EventID 2** when a file's creation timestamp is modified, a technique commonly called "timestomping." This is a **low-volume, high-value event type** that detects anti-forensics activity where attackers modify file timestamps to hide malicious files by making them appear legitimate or to blend in with existing files in a directory.

Detection Value and Why It Matters
-----------------------------------

Timestomping is a classic anti-forensics technique used to evade detection and complicate incident response:

**Hiding Malicious Files**: Attackers modify file timestamps to make malicious files appear legitimate:
* Setting creation time to match other files in `C:\Windows\System32\` to blend in
* Backdating files to make them appear as part of the original system installation
* Matching timestamps of legitimate applications to avoid suspicion

**Evading Timeline Analysis**: Forensic investigators rely on file timestamps to construct attack timelines. Timestomping disrupts this analysis by:
* Making recently created malware appear old
* Hiding the true time of file creation or modification
* Breaking the correlation between related attacker activities

**Persistence Mechanism Concealment**: Attackers timestamp persistence mechanisms (scheduled tasks, startup folder items, registry run keys) to appear as if they've existed for a long time, making them less likely to be noticed during security reviews.

**MITRE ATT&CK Mapping**:
* **T1070.006 - Indicator Removal on Host: Timestomp** - Primary technique
* **T1564 - Hide Artifacts** - General technique category for hiding evidence

Why Attackers Use Timestomping
-------------------------------

Timestomping helps attackers in several ways:

1. **Evades "Recent Files" Detection**: Security tools and analysts often filter for recently created/modified files. Timestomped files won't appear in these searches.

2. **Blends with Legitimate Files**: When all files in `C:\Windows\System32\` were created during Windows installation except one created yesterday, that one file stands out. Timestomping eliminates this tell.

3. **Complicates Forensics**: Without accurate timestamps, investigators struggle to:
   - Determine when compromise occurred
   - Correlate file creation with other events
   - Establish attacker dwell time

4. **Defeats SIEM Time-Based Queries**: Many detection rules look for file creation within specific time windows. Timestomping can evade these.

Volume Characteristics
-----------------------

File creation time modification is rare in normal operations:
* **Normal operations**: Some applications legitimately modify timestamps (installers, cloud sync tools like OneDrive, backup software)
* **Typical volume**: 10-50 events per day, mostly from known applications
* **Servers**: Near-zero volume outside of software installations

This low volume makes timestomping detection ideal for a **targeted include approach** focusing on user directories and suspicious file types, or an **exclusion-based approach** that logs everything except known-good applications.

How Timestomping Works
-----------------------

Attackers use various tools and methods to modify file timestamps:

**PowerShell**:
```powershell
$(Get-Item malware.exe).creationtime=$(Get-Date "01/01/2020 12:00 am")
```

**Command Line Tools**:
* `timestomp.exe` (from Metasploit)
* `NewFileTime.exe`
* Custom scripts and tools

**Windows API**:
* `SetFileTime()` API calls from custom malware
* Can modify creation, modification, and access times

Sysmon monitors file system API calls and detects when the creation time is changed from its original value.

What to Investigate
--------------------

When reviewing file creation time change events, prioritize investigation of:

**1. Timestomping in System Directories**
* Files in `C:\Windows\`, `C:\Windows\System32\`, or `C:\Windows\SysWOW64\`
* Particularly suspicious if done by non-system processes
* System files should rarely have timestamps modified post-installation

**2. Timestomping in User Directories**
* Files in `C:\Users\<username>\AppData\` directories
* Downloads folder (`C:\Users\<username>\Downloads\`)
* Startup folders and other persistence locations
* Desktop and Documents folders

**3. Executable and Script Files**
* `.exe`, `.dll`, `.sys` files being timestomped
* PowerShell scripts (`.ps1`, `.psm1`)
* Batch files, VBScript, JavaScript
* Any file that can execute code

**4. Suspicious Processes Performing Timestomping**
* PowerShell, CMD, or scripting engines modifying timestamps
* Processes from temp directories
* Unknown or recently created processes
* Tools known for timestomping (`timestomp.exe`, `NewFileTime.exe`)

**5. Multiple Files Timestomped Simultaneously**
* Batch timestomping operations (attacker cleaning up multiple files)
* All files set to same timestamp (common attacker pattern)
* Rapid sequence of timestamp modifications

**6. Timing and Context**
* Timestomping shortly after file creation (covering tracks)
* Correlates with other suspicious activity (malware execution, lateral movement)
* Occurs during off-hours or after compromise indicators

**7. Timestamp Anomalies**
* CreationTime set to far in the past (e.g., 1999, Windows XP era)
* CreationTime set to match Windows installation date
* Identical timestamps across multiple unrelated files

Event Fields
------------

The file creation time change event fields are:

* **RuleName**: Name of rule that triggered the event
* **UtcTime**: Time in UTC when the timestamp modification was detected
* **ProcessGuid**: Process GUID of the process that changed the file creation time
* **ProcessId**: Process ID of the process changing the file creation time
* **Image**: File path of the process that changed the file creation time
* **TargetFilename**: Full path of the file whose timestamp was modified
* **CreationUtcTime**: New (modified) creation time of the file
* **PreviousCreationUtcTime**: Original creation time before modification

The **PreviousCreationUtcTime** and **CreationUtcTime** fields are critical - compare them to understand how the timestamp was changed and whether it's suspicious.

Configuration Examples
-----------------------

**Example 1: Monitor User Directories (Recommended)**

Focus on timestomping in user directories where attackers commonly operate:

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileCreateTime onmatch="include">
                <!-- Monitor all timestamp changes in user directories -->
                <TargetFilename condition="begin with">C:\Users\</TargetFilename>
            </FileCreateTime>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 2: Monitor High-Value File Types and Locations**

Target specific file types and system directories:

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileCreateTime onmatch="include">
                <!-- User directories -->
                <TargetFilename condition="begin with">C:\Users\</TargetFilename>

                <!-- System directories (very suspicious) -->
                <TargetFilename condition="begin with">C:\Windows\System32\</TargetFilename>
                <TargetFilename condition="begin with">C:\Windows\SysWOW64\</TargetFilename>

                <!-- Executable and script files anywhere -->
                <Rule groupRelation="or">
                    <TargetFilename condition="end with">.exe</TargetFilename>
                    <TargetFilename condition="end with">.dll</TargetFilename>
                    <TargetFilename condition="end with">.sys</TargetFilename>
                    <TargetFilename condition="end with">.ps1</TargetFilename>
                    <TargetFilename condition="end with">.bat</TargetFilename>
                    <TargetFilename condition="end with">.cmd</TargetFilename>
                    <TargetFilename condition="end with">.vbs</TargetFilename>
                </Rule>
            </FileCreateTime>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 3: Exclusion-Based Approach (Log All, Exclude Known-Good)**

Log all timestamp modifications but exclude applications that legitimately change timestamps:

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="Include All Timestomping" groupRelation="or">
            <FileCreateTime onmatch="include">
                <!-- Include all timestamp modifications -->
                <TargetFilename condition="begin with">C:\</TargetFilename>
            </FileCreateTime>
        </RuleGroup>

        <RuleGroup name="Exclude Known-Good Applications" groupRelation="or">
            <FileCreateTime onmatch="exclude">
                <!-- Cloud sync tools -->
                <Image condition="end with">OneDrive.exe</Image>
                <Image condition="contains">Dropbox\</Image>
                <Image condition="contains">Google Drive\</Image>

                <!-- Installers and update processes -->
                <Image condition="contains">setup</Image>
                <Image condition="contains">install</Image>
                <Image condition="contains">Update\</Image>
                <Image condition="end with">redist.exe</Image>
                <Image condition="is">C:\Windows\System32\msiexec.exe</Image>
                <Image condition="is">C:\Windows\servicing\TrustedInstaller.exe</Image>

                <!-- System processes -->
                <Image condition="is">C:\Windows\System32\backgroundTaskHost.exe</Image>
                <Image condition="is">C:\Windows\System32\svchost.exe</Image>

                <!-- Backup software (add specific tools as discovered) -->
                <!-- <Image condition="contains">Backup\</Image> -->
            </FileCreateTime>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 4: Detect Suspicious Processes Doing Timestomping**

Focus on processes commonly used by attackers:

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileCreateTime onmatch="include">
                <!-- PowerShell timestomping -->
                <Image condition="end with">powershell.exe</Image>
                <Image condition="end with">pwsh.exe</Image>

                <!-- Command line utilities -->
                <Image condition="end with">cmd.exe</Image>
                <Image condition="end with">cscript.exe</Image>
                <Image condition="end with">wscript.exe</Image>

                <!-- Known timestomping tools -->
                <Image condition="contains">timestomp</Image>
                <Image condition="contains">NewFileTime</Image>

                <!-- Suspicious locations -->
                <Image condition="contains">\Temp\</Image>
                <Image condition="contains">\AppData\Local\Temp\</Image>
                <Image condition="contains">\Downloads\</Image>
            </FileCreateTime>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

Investigation Workflow
-----------------------

When you detect a file creation time change event:

1. **Identify the File**: Check `TargetFilename` - what file was timestomped?
   - Is it an executable, script, or DLL?
   - Is it in a sensitive location (System32, user startup folders)?

2. **Analyze the Process**: Check `Image` - what process modified the timestamp?
   - Is it a known-good application (installer, cloud sync)?
   - Is it suspicious (PowerShell, unknown tool)?

3. **Compare Timestamps**:
   - `PreviousCreationUtcTime`: When was the file actually created?
   - `CreationUtcTime`: What timestamp was it changed to?
   - Is the new timestamp trying to make the file look old?

4. **Correlate with Other Events**:
   - Check Process Creation events: Was the file recently created?
   - Check File Creation events: What process created the file originally?
   - Check Network Connections: Did the process that created the file connect to external IPs?

5. **Examine the File**:
   - Hash the timestomped file and check threat intelligence
   - Analyze the file for malicious indicators
   - Check if it's signed and by whom

6. **Timeline Analysis**:
   - When was the file really created (PreviousCreationUtcTime)?
   - What else happened around that time?
   - Does this correlate with known compromise indicators?

Common Legitimate Use Cases
----------------------------

Not all timestamp modifications are malicious. Legitimate reasons include:

* **Cloud Sync Tools**: OneDrive, Dropbox, Google Drive modify timestamps to match server-side timestamps
* **Backup/Restore Operations**: Backup tools may restore original timestamps when restoring files
* **Software Installers**: Some installers set specific timestamps on installed files
* **Development Tools**: Version control systems (Git) may restore file timestamps during checkout
* **Archive Extraction**: Extracting ZIP/RAR files often restores original timestamps

The key is to baseline your environment and understand what's normal for your systems, then investigate deviations.

Best Practices
---------------

1. **Start with User Directories**: Monitoring `C:\Users\` captures most attacker activity while minimizing noise
2. **Baseline Your Environment**: Understand which applications legitimately modify timestamps
3. **Progressive Exclusions**: Start broad, add exclusions for verified legitimate applications
4. **Focus on Executables**: Prioritize monitoring of `.exe`, `.dll`, `.ps1` timestomping
5. **Correlate with Other Events**: Timestomping alone may be benign; correlation with other suspicious activity increases confidence
6. **Regular Review**: Periodically review timestomping events to identify new patterns or threats

Evasion and Limitations
------------------------

**Attacker Evasion Techniques:**
* Some attackers avoid timestomping entirely, knowing it's monitored
* Can set timestamps to random values throughout a time range to appear less suspicious
* May use kernel-mode rootkits to hide timestomping from Sysmon

**Sysmon Limitations:**
* Only detects modification of creation time, not modification or access times (Windows doesn't log those separately)
* Cannot detect timestomping that occurs before Sysmon is installed
* Kernel-mode tampering may evade detection

Summary
-------

File creation time change monitoring (EventID 2) detects a common anti-forensics technique used by sophisticated attackers. The low event volume and high detection value make it ideal for:
* Targeted monitoring of user directories
* Detecting timestomping of executable files
* Identifying anti-forensics activity during incident response
* Complementing other detection mechanisms in a layered defense strategy

When configured properly with appropriate exclusions for legitimate applications, timestomping detection provides high-fidelity alerts with minimal false positives.
