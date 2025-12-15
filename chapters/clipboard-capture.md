Clipboard Capture
=================

Sysmon will log **EventID 24** when applications store text in the clipboard. This capability was added in Sysmon version 12.0 with schema 4.40. Clipboard monitoring is a **low-volume, high-sensitivity event type** that provides unique visibility into data theft but comes with significant privacy and security considerations that require careful deployment planning.

Detection Value and Why It Matters
-----------------------------------

Clipboard monitoring detects data theft techniques that are difficult to observe through other telemetry:

**Credential Theft via RDP/Remote Sessions**: Attackers and penetration testers commonly:
* Copy credentials from password managers on their local machine
* Paste credentials into RDP sessions to compromised servers
* Transfer authentication tokens or API keys via clipboard
* Move data between compromised systems using clipboard redirection

**Data Exfiltration**: Attackers use the clipboard to stage data for exfiltration:
* Copy sensitive documents, code, or configuration data
* Transfer small amounts of data between systems via remote sessions
* Exfiltrate data from environments where file transfer is restricted

**Lateral Movement Evidence**: Clipboard content can reveal:
* Commands being copy-pasted across multiple systems
* Credentials being reused across the environment
* PowerShell scripts or commands being staged for execution

**MITRE ATT&CK Mapping**:
* **T1115 - Clipboard Data** - Accessing clipboard for credential or data theft
* **T1056.001 - Input Capture: Keylogging** - Related technique for capturing user input
* **T1021.001 - Remote Services: Remote Desktop Protocol** - RDP sessions where clipboard is commonly used

Privacy and Security Considerations
------------------------------------

**Critical Privacy Warning**: Clipboard capture is an **extremely sensitive capability** that can expose private, confidential, and legally protected information. Clipboard data may contain:
* Passwords, API keys, and authentication tokens
* Personal identifiable information (PII)
* Protected health information (PHI)
* Financial data, credit card numbers
* Confidential business information
* Private communications

**Data Protection Requirements:**

Clipboard data is stored as files in the archive directory (same location as File Delete archived files), **NOT in the event log**. The archive directory is protected by SYSTEM-level ACLs:
* Only SYSTEM account can access the files
* Must use PsExec or similar tool to read: `PsExec.exe -sid cmd`
* Files are named by their hash value
* Encryption at rest is critical if storing sensitive clipboard data

**Legal and Compliance Risks:**
* May violate privacy laws (GDPR, CCPA) if not properly disclosed
* Could capture attorney-client privileged communications
* May require consent depending on jurisdiction
* Data retention policies must be carefully considered
* Access controls and audit logging are essential

When to Use Clipboard Monitoring
---------------------------------

**Recommended Use Cases:**
* **RDP-enabled servers** exposed to untrusted networks (bastion hosts, jump servers)
* **Privileged access workstations** (PAWs) used for administrative tasks
* **High-value targets** where credential theft is a primary concern
* **Honeypot systems** where any clipboard activity is inherently suspicious
* **Incident response** during active investigations (temporary deployment)

**NOT Recommended:**
* **General user workstations** - Privacy risks far outweigh detection value
* **Developer workstations** - Will capture code, credentials, and sensitive data constantly
* **Environments without strong data protection controls**
* **Systems where users are not informed** about clipboard monitoring

**Critical Requirement**: Users and administrators **must be informed** that clipboard monitoring is active. Accidental capture of sensitive data in legitimate workflows is common, particularly in RDP environments.

Volume Characteristics
-----------------------

Clipboard capture volume varies significantly:
* **RDP jump servers**: Moderate volume (10-50 events per day per active session)
* **Interactive user workstations**: High volume (hundreds of events per day)
* **Servers without interactive sessions**: Very low volume (near zero)

The volume depends entirely on user behavior - how often they copy and paste text.

How Clipboard Monitoring Works
-------------------------------

When enabled, Sysmon monitors the Windows clipboard API and logs whenever text is stored:
1. Application writes text to clipboard
2. Sysmon intercepts the clipboard write
3. Event is logged with metadata (process, session, client info)
4. Clipboard text is saved to archive directory as a file (named by hash)
5. EventID 24 references the file by hash

**Important**: Only **text** clipboard data is captured. Images, files, and other clipboard formats are not logged.

**Enabling Clipboard Capture:**
Add the `<CaptureClipboard/>` element under the main `<Sysmon>` element in your configuration:

```xml
<Sysmon schemaversion="4.40">
  <CaptureClipboard />
  <ArchiveDirectory>SecureClipboardArchive</ArchiveDirectory>
  <!-- Event filtering rules follow -->
</Sysmon>
```

Without `<CaptureClipboard/>`, clipboard events are not generated even if filtering rules are present.

What to Investigate
--------------------

When reviewing clipboard capture events, prioritize investigation of:

**1. RDP Session Clipboard Activity**
* Clipboard usage during remote desktop sessions (Session field != 0)
* ClientInfo shows remote hostname and IP address
* Particularly suspicious during off-hours or from unexpected IP ranges

**2. Suspicious Processes Accessing Clipboard**
* PowerShell, CMD, scripting engines writing to clipboard
* Processes from temp directories or unusual locations
* Malware sometimes uses clipboard for C2 communication or data staging

**3. Session Analysis**
* Session field indicates session type:
  - Session 0: System/service context (very unusual for clipboard use)
  - Session 1+: Interactive or RDP sessions
* Correlate clipboard activity with logon events to identify user

**4. Patterns Indicating Credential Theft**
* Multiple clipboard writes in quick succession during RDP session
* Clipboard activity immediately after connecting to RDP session
* Review archived clipboard files for credential patterns (manually, with care)

**5. Data Exfiltration Indicators**
* Large amounts of clipboard activity during suspected compromise
* Clipboard use correlating with network connections to external IPs
* Repeated clipboard writes of similar content

**6. Unexpected Clipboard Sources**
* Services or system processes writing to clipboard (unusual)
* Clipboard activity on servers that should have minimal interactive use

Event Fields
------------

The clipboard capture event fields are:

* **RuleName**: Name of rule that triggered the event
* **UtcTime**: Time in UTC when event was created
* **ProcessGuid**: Process GUID of the process that stored text in clipboard
* **ProcessId**: Process ID of the process that stored text in clipboard
* **Image**: File path of the process that wrote to the clipboard
* **Session**: Session ID where the process is running (0 = system, 1+ = interactive/remote)
* **ClientInfo**: Contains session username, and for remote sessions: originating hostname and IP address
* **Hashes**: Hash of the clipboard text file (also the filename in archive directory)
* **Archived**: Status indicating whether text was successfully stored in archive directory (`true` or `false`)

Configuration Examples
-----------------------

**Example 1: Capture All Clipboard Activity (High Privacy Risk)**

This configuration logs all clipboard events with no filtering:

```xml
<Sysmon schemaversion="4.40">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation />
  <CaptureClipboard />
  <ArchiveDirectory>SecureClipboardArchive</ArchiveDirectory>
  <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ClipboardChange onmatch="exclude">
            <!-- Log everything - use only on dedicated RDP jump servers -->
         </ClipboardChange>
      </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Recommended only for**: Jump servers, PAWs, honeypots where all clipboard use is monitored by design.

**Example 2: Monitor Only Remote RDP Sessions**

Capture clipboard activity only during RDP sessions, not local interactive sessions:

```xml
<Sysmon schemaversion="4.40">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CaptureClipboard />
  <ArchiveDirectory>SecureClipboardArchive</ArchiveDirectory>
  <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ClipboardChange onmatch="include">
            <!-- Capture rdpclip.exe (RDP clipboard redirection process) -->
            <Image condition="end with">rdpclip.exe</Image>
         </ClipboardChange>
      </RuleGroup>
  </EventFiltering>
</Sysmon>
```

This focuses on RDP clipboard transfers, reducing noise from local clipboard use.

**Example 3: Monitor Suspicious Processes Only**

Capture clipboard use by processes commonly abused by attackers:

```xml
<Sysmon schemaversion="4.40">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CaptureClipboard />
  <ArchiveDirectory>SecureClipboardArchive</ArchiveDirectory>
  <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ClipboardChange onmatch="include">
            <!-- Scripting engines -->
            <Image condition="end with">powershell.exe</Image>
            <Image condition="end with">cmd.exe</Image>
            <Image condition="end with">cscript.exe</Image>
            <Image condition="end with">wscript.exe</Image>

            <!-- RDP clipboard -->
            <Image condition="end with">rdpclip.exe</Image>

            <!-- Processes from suspicious locations -->
            <Image condition="contains">\Temp\</Image>
            <Image condition="contains">\AppData\Local\Temp\</Image>
         </ClipboardChange>
      </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Example 4: Exclude Known Noisy Applications**

Start with broad coverage but exclude applications that generate excessive noise:

```xml
<Sysmon schemaversion="4.40">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CaptureClipboard />
  <ArchiveDirectory>SecureClipboardArchive</ArchiveDirectory>
  <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ClipboardChange onmatch="exclude">
            <!-- Exclude known applications with high clipboard use -->
            <Image condition="is">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Image>
            <Image condition="is">C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE</Image>
            <Image condition="contains">\Microsoft VS Code\</Image>

            <!-- Exclude browsers -->
            <Image condition="contains">\Google\Chrome\Application\chrome.exe</Image>
            <Image condition="contains">\Mozilla Firefox\firefox.exe</Image>
         </ClipboardChange>
      </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Important Limitations and Warnings
-----------------------------------

**Hyper-V and RDP Console Exposure**: In Hyper-V environments where Sysmon is configured for clipboard capture, **selecting a VM console window from Hyper-V Manager** can trigger clipboard events because Hyper-V uses RDP for displaying VM UI. This can accidentally expose clipboard contents from the host system. Administrators must be aware of this behavior.

**Example Event**: RDP clipboard capture from Hyper-V console session:

```xml
<EventData>
  <Data Name="Image">C:\Windows\System32\rdpclip.exe</Data>
  <Data Name="Session">1</Data>
  <Data Name="ClientInfo">user: acmelabs\Admin ip: FE80::013E:52B8:0C83:3DE3 hostname: DESKTOP-LH0AJLB</Data>
  <Data Name="Archived">true</Data>
</EventData>
```

**Clipboard Data Is Not in Event Log**: The actual clipboard text is stored in the archive directory as files, not in the event log. This means:
* SIEM ingestion captures metadata only, not clipboard content
* To review clipboard content, you must access the archive directory with SYSTEM privileges
* Clipboard files must be secured with encryption at rest and access controls
* Retention policies for clipboard files must be defined and enforced

**No Image/File Capture**: Only text clipboard data is captured. Copy-pasting files, images, or other non-text formats does not generate EventID 24.

Best Practices for Clipboard Monitoring
----------------------------------------

1. **Minimize Deployment Scope**: Only enable on systems where the detection value clearly outweighs privacy risks
2. **User Notification**: Inform users and administrators that clipboard monitoring is active
3. **Secure Archive Directory**:
   - Use strong ACLs (SYSTEM-only by default is good)
   - Encrypt at rest
   - Implement retention policies
   - Monitor access to clipboard archive files
4. **Legal Review**: Consult legal/compliance teams before deployment
5. **Regular Review**: Periodically verify clipboard monitoring is still necessary
6. **Incident Response**: Consider enabling temporarily during active investigations rather than continuous monitoring
7. **Data Minimization**: Use targeted filtering to capture only necessary clipboard events
8. **Audit Access**: Log and monitor any access to archived clipboard files

Data Retention and Cleanup
---------------------------

Clipboard archive files accumulate over time. Implement a retention policy:
* Define maximum retention period (e.g., 30 days, 90 days)
* Automate cleanup of old clipboard files
* Document retention policy for compliance
* Ensure cleanup process preserves files needed for active investigations

Example PowerShell cleanup script (run as SYSTEM):
```powershell
# Delete clipboard files older than 30 days
$archivePath = "C:\SecureClipboardArchive"
$retentionDays = 30
Get-ChildItem -Path $archivePath -File |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$retentionDays) } |
    Remove-Item -Force
```

Summary
-------

Clipboard capture (EventID 24) is a powerful but sensitive capability:
* **Use sparingly**: RDP jump servers, PAWs, honeypots
* **Privacy first**: Consider legal, ethical, and privacy implications
* **Inform users**: Transparency is essential
* **Secure the data**: Strong access controls and encryption
* **Define retention**: Clear policies for data lifecycle

When deployed appropriately with proper safeguards, clipboard monitoring provides unique visibility into credential theft and data exfiltration during remote sessions.
