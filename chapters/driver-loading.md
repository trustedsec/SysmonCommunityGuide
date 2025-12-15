Driver Loading
==============

Sysmon will log **EventID 6** for the loading of kernel drivers. Driver loading is a **low-volume, high-value event type** that should typically log all occurrences with minimal filtering. Drivers operate at the kernel level with the highest privileges on a system, making malicious driver loading one of the most dangerous attack techniques.

Detection Value and Why It Matters
-----------------------------------

Kernel drivers have unrestricted access to the operating system and can:
* Bypass all user-mode security controls
* Hide processes, files, and registry keys (rootkits)
* Intercept and modify system calls
* Disable security software
* Access protected memory (credential theft)
* Persist across reboots with highest privileges

Attackers use malicious drivers for:

**Rootkit Installation**: Drivers that hide malware presence by intercepting system APIs and filtering out malicious processes, files, and network connections from being detected.

**Security Tool Bypass**: Drivers like those used by Mimikatz (mimidrv.sys) to query and modify kernel memory to bypass process protections, read credentials from protected processes like LSASS, or disable security callbacks.

**Bring Your Own Vulnerable Driver (BYOVD)**: Attackers exploit known-vulnerable but legitimately signed drivers to gain kernel-level code execution. These vulnerable drivers are catalogued at **https://www.loldrivers.io/**, which maintains a comprehensive list of drivers known to be exploitable. The LOLDrivers project provides a ready-to-use Sysmon configuration for detecting these vulnerable drivers: **https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon**

**Privilege Escalation**: Exploiting vulnerable signed drivers to escalate from user-mode to kernel-mode execution.

**Persistence**: Drivers load early in the boot process, before most security tools, providing attackers with early system control.

**MITRE ATT&CK Mapping**: Driver loading events help detect:
* **T1014 - Rootkit**: Kernel-mode rootkits hiding attacker presence
* **T1068 - Exploitation for Privilege Escalation**: Exploiting vulnerable drivers (BYOVD)
* **T1543.003 - Create or Modify System Process: Windows Service**: Driver-based services
* **T1562 - Impair Defenses**: Drivers that disable security tools
* **T1611 - Escape to Host**: Breaking out of virtualization using drivers

Why Driver Loading is Low-Volume
---------------------------------

Unlike process creation or file creation, driver loading happens infrequently:
* Drivers load primarily at boot time
* New driver installation is rare (hardware additions, software updates)
* Typical system generates only 10-50 driver load events per day
* Most are well-known, signed Windows or hardware vendor drivers

This low volume makes driver loading ideal for a **log-all approach**. The small event count allows you to review all driver loads and progressively exclude known-good drivers without overwhelming your SIEM.

Configuration Strategy: Log All, Exclude Known-Good
----------------------------------------------------

The recommended approach for driver loading:

1. **Start by logging everything** - No initial exclusions
2. **Baseline for 1-2 weeks** - Collect all driver loads in your environment
3. **Identify legitimate drivers** - Review unique driver signatures and validate they are expected
4. **Integrate LOLDrivers detection** - Add the LOLDrivers Sysmon configuration to detect known-vulnerable drivers
5. **Progressively exclude** - Add exclusions for verified, signed drivers from trusted vendors
6. **Continuous monitoring** - Review any new drivers that appear

**Critical**: Always filter on **both Signature AND SignatureStatus**. Many attacks use stolen code-signing certificates that are later revoked. Checking that SignatureStatus is "Valid" helps detect:
* Drivers signed with stolen certificates before revocation
* Drivers signed with certificates that have since been revoked
* Legitimate vendors forced to revoke certificates due to abuse

Certificate Revocation Checking
--------------------------------

Enable certificate revocation checking in your Sysmon configuration using `<CheckRevocation/>`. This tells Sysmon to verify that signing certificates have not been revoked. While this adds a small performance overhead (network lookup to check revocation status), it provides critical security value for detecting abuse of stolen certificates.

Leveraging LOLDrivers Project
------------------------------

The LOLDrivers project (https://www.loldrivers.io/) is an invaluable resource for detecting BYOVD attacks. The project maintains:
* A curated list of vulnerable drivers known to be exploited by attackers
* Driver hashes, signatures, and metadata
* A ready-to-use Sysmon configuration that detects loading of these vulnerable drivers

**To integrate LOLDrivers detection:**
1. Download the Sysmon configuration from: https://github.com/magicsword-io/LOLDrivers/tree/main/detections/sysmon
2. Merge it with your existing driver loading configuration
3. The configuration uses driver hashes to detect known-vulnerable drivers regardless of how they are signed
4. Regularly update the configuration as new vulnerable drivers are discovered

This is particularly valuable because vulnerable but signed drivers are difficult to detect through signature validation alone - they are legitimately signed by vendors but contain exploitable vulnerabilities.


![process](./media/image48.png)

Initial rule for collecting DriverLoad events

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <!--Filter none driver default rule events-->
            <ProcessCreate onmatch = "include">
            </ProcessCreate>
            <ProcessTerminate onmatch = "include">
            </ProcessTerminate>
            <FileCreate onmatch = "include">
            </FileCreate>
            <FileCreateTime onmatch = "include">
            </FileCreateTime>

            <!--Include all driver events-->
            <DriverLoad onmatch="exclude">
            </DriverLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

Collect unique Signature field values for building filters

The event fields are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ImageLoaded**: File path of the driver loaded

* **Hashes**: Hashes captured by Sysmon driver

* **Signed**: Is the driver loaded signed

* **Signature**: Signer name of the driver

* **SignatureStatus**: Status of the signature

What to Investigate
--------------------

When reviewing driver loading events, prioritize:

**1. Unsigned Drivers**
* Any driver that is not signed should be investigated immediately
* Legitimate drivers from major vendors are always signed
* Unsigned drivers are strong indicators of malicious activity

**2. Drivers with Invalid Signatures**
* SignatureStatus not equal to "Valid"
* May indicate stolen/revoked certificates or tampered drivers
* Cross-reference with LOLDrivers database

**3. Drivers from Unusual Vendors**
* Drivers signed by unknown or suspicious vendors
* Particularly suspicious if loaded on servers or systems that don't match the hardware
* Example: Gaming peripheral drivers on a server

**4. Known-Vulnerable Drivers**
* Drivers matching hashes in the LOLDrivers database
* Even if properly signed, these are exploitable
* Common in BYOVD attacks

**5. Drivers Loaded from Unusual Locations**
* Drivers outside of `C:\Windows\System32\drivers\`
* Drivers from temp directories or user folders
* Drivers on removable media

**6. Mimikatz and Tool-Specific Drivers**
* mimidrv.sys (Mimikatz driver)
* Other known attack tool drivers
* Monitor for these by name and hash

**7. Recent Driver Installations**
* Any new driver that appears after your baseline period
* Investigate the timing - did it coincide with other suspicious activity?
* Validate business justification for new driver

Example Configuration: Filtering Known-Good Drivers
----------------------------------------------------

After baselining, exclude verified signed drivers from trusted vendors (example for a VDI environment):

```xml
<Sysmon schemaversion="4.22">
    <CheckRevocation/>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <DriverLoad onmatch="exclude">
                <!--Exclude signed Microsoft drivers-->
                <Rule groupRelation="and">
                    <Signature condition="contains">Microsoft</Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
                <!--Exclude signed Inter drivers-->
                <Rule groupRelation="and">
                    <Signature condition="begin with">Intel </Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
                <!--Exclude signed VMware drivers-->
                <Rule groupRelation="and">
                    <Signature condition="begin with">VMware</Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
            </DriverLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
