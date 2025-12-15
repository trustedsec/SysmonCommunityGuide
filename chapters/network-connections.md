Network Connections
===================

Sysmon will log **EventID 3** for all TCP and UDP network connections made by processes on the system. Network connection monitoring is critical for detection engineering because it provides visibility into command and control communications, lateral movement, data exfiltration, and initial access attempts. However, this is also one of the highest-volume event types Sysmon can generate, requiring careful configuration to balance visibility with manageability.

Detection Value and Use Cases
------------------------------

Network connection logging provides insight into several critical attack phases:

**Command and Control (C2)**: After initial compromise, attackers establish communication channels to remotely control infected systems. Network connection logs help detect:
* Beaconing patterns to external IP addresses
* Connections to known malicious infrastructure
* Unusual protocols or ports for outbound communication
* Communication from processes that should not make network connections

**Lateral Movement**: Attackers move between systems within a network using various protocols. Network logs capture:
* SMB connections between workstations (unusual peer-to-peer traffic)
* RDP or WinRM connections from unexpected sources
* Administrative tool usage across systems
* Pass-the-hash and other credential theft-based movement

**Data Exfiltration**: When attackers steal data, they must transmit it somewhere. Network monitoring detects:
* Large volume transfers to external destinations
* Connections to cloud storage or file sharing services from unusual processes
* Data moving to geographic regions where your organization does not operate
* Exfiltration through unusual protocols or applications

**Living Off the Land**: Attackers abuse legitimate Windows tools to avoid detection. Network logs help identify when built-in tools make suspicious connections:
* PowerShell connecting to the internet
* cmd.exe, wscript.exe, or certutil.exe downloading files
* Administrative tools like wmic.exe or sc.exe used remotely
* Compilation tools like msbuild.exe fetching remote resources

**MITRE ATT&CK Mapping**: Network connection events help detect numerous techniques:
* **T1071 - Application Layer Protocol**: C2 communication over standard protocols
* **T1095 - Non-Application Layer Protocol**: C2 using custom protocols
* **T1041 - Exfiltration Over C2 Channel**: Data theft via command and control
* **T1048 - Exfiltration Over Alternative Protocol**: Using uncommon channels for data theft
* **T1021 - Remote Services**: RDP, SMB, WinRM for lateral movement
* **T1090 - Proxy**: Using proxies or tunnels to obscure communication
* **T1105 - Ingress Tool Transfer**: Downloading additional attack tools

Volume Challenges and Configuration Philosophy
-----------------------------------------------

Network connections are extremely high-volume. A typical Windows workstation generates hundreds to thousands of network connections per hour through:
* Web browsers making dozens of connections per webpage
* Cloud applications constantly syncing data
* Operating system telemetry and update checks
* Background applications and services
* Email clients, chat applications, collaboration tools

On servers, especially domain controllers or application servers, network connection volume can reach tens of thousands per hour. Logging all connections without filtering will:
* Overwhelm your SIEM with millions of events daily
* Consume significant storage
* Make it nearly impossible to find meaningful detections in the noise
* Impact Sysmon and system performance

This event type requires either an **outlier-based exclusion approach** (filter out known-good, log everything else) or a **targeted include approach** (only log specific suspicious processes or ports). Many organizations use a hybrid strategy.

Critical Warning: Cloud Service Abuse
--------------------------------------

**Do NOT blindly exclude all cloud service connections.** Attackers frequently abuse legitimate cloud tools and services to blend in with normal traffic and evade perimeter monitoring. Be extremely cautious when considering exclusions for cloud-related processes.

**Known Attack Patterns Using Cloud Services:**

* **cloudflared.exe** (Cloudflare Tunnel) - Attackers use this legitimate Cloudflare tool to tunnel SSH, RDP, and Remote Monitoring and Management (RMM) tool connections through Cloudflare's network. This bypasses traditional perimeter controls and appears as normal HTTPS traffic to Cloudflare infrastructure. Always log cloudflared.exe connections and investigate unexpected usage.

* **cmd5.exe** (AWS CLI) - Attackers have used modified or legitimate versions of AWS command-line tools for data exfiltration to AWS S3 buckets. If your organization does not routinely use AWS CLI tools on endpoints, these should always be logged.

* **rclone** - This legitimate cloud storage synchronization tool is heavily abused by attackers for data exfiltration to various cloud storage providers (Google Drive, Dropbox, OneDrive, Mega, etc.). Attackers use rclone because it can transfer large amounts of data to cloud storage while appearing as normal cloud sync traffic, evading perimeter data loss prevention (DLP) monitoring.

* **Cloud Storage Client Abuse** - Legitimate sync clients (OneDrive, Google Drive, Dropbox) can be abused to exfiltrate data by attackers who install them or use existing installations with attacker-controlled accounts.

**Best Practice**: Instead of excluding cloud tools, implement **conditional monitoring**:
* Log cloud tool usage from unexpected user accounts
* Log cloud tools running from unusual paths (temp directories, user downloads)
* Monitor for cloud tools on servers where they should not exist
* Track volume of data transferred by cloud tools
* Alert on first-time usage of cloud tools in your environment

Configuration Strategies
-------------------------

**Strategy 1 - Targeted Includes for Suspicious Processes (Recommended for Most)**

The most practical approach for most organizations is to only log network connections from processes that should rarely or never make network connections. This dramatically reduces volume while capturing the most valuable detections.

**Strategy 2 - Exclusion-Based with Aggressive Filtering**

Some organizations with sufficient SIEM capacity log all connections but exclude high-volume, known-good applications. This provides broader visibility but requires more storage and processing.

**Strategy 3 - Hybrid Approach**

Combine both strategies: include specific suspicious processes and exclude specific high-volume benign applications, logging everything else that falls between.

**Important DNS Lookup Note**: The DestinationHostname field uses the GetNameInfo API for reverse DNS lookups. This is often unreliable - it may return CDN names, may have no information, or may be spoofable. Since Sysmon v11.0, you can disable this behavior using ```<DnsLookup>False</DnsLookup>``` at the root of the configuration file. Disabling DNS lookup also improves performance and reduces dependencies on network availability.

**Port Name Consideration**: The DestinationPortName field uses GetNameInfo API for friendly port names. On systems where services run under svchost.exe, most connections will show svchost.exe as the source process.

The fields for the event are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process GUID of the process that made the network connection

* **ProcessId**: Process ID used by the OS to identify the process that made the network connection

* **Image**: File path of the process that made the network connection

* **User**: Name of the account who made the network connection

* **Protocol**: Protocol being used for the network connection

* **Initiated**: Indicated process-initiated TCP connection

* **SourceIsIpv6**: Is the source IP an Ipv6

* **SourceIp**: Source IP address that made the network connection

* **SourceHostname**: DNS name of the host that made the network connection

* **SourcePort**: Source port number

* **SourcePortName**: Name of the source port being used

* **DestinationIsIpv6**: Is the destination IP an Ipv6

* **DestinationIp**: IP address destination

* **DestinationHostname**: DNS name of the host that is contacted

* **DestinationPort**: Destination port number

* **DestinationPortName**: Name of the destination port


Configuration Examples
----------------------

**Example 1: Targeted Includes for Living Off the Land Binaries**

This configuration only logs network connections from Windows built-in tools and commonly abused utilities:

```xml
<Sysmon schemaversion="4.22">
   <EventFiltering>
 <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
            <!--Native Windows tools - Living off the land-->
            <Image name="technique_id=T1053,technique_name=Scheduled Task" condition="image">at.exe</Image> <!--Microsoft:Windows: Remote task scheduling | Credit @ion-storm -->
            <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image> <!--Microsoft:Windows: Certificate tool can contact outbound | Credit @ion-storm and @FVT [ https://twitter.com/FVT/status/834433734602530817 ] -->
            <Image condition="image">cmd.exe</Image> <!--Microsoft:Windows: Command prompt-->
            <Image name="technique_id=T1218,technique_name=Signed Script Proxy Execution" condition="image">cscript.exe</Image><!--Microsoft:WindowsScriptingHost: | Credit @Cyb3rOps [ https://gist.github.com/Neo23x0/a4b4af9481e01e749409 ] -->
            <Image condition="image">java.exe</Image> <!--Java: Monitor usage of vulnerable application | Credit @ion-storm -->
            <Image name="technique_id=T1170,technique_name=Mshta" condition="image">mshta.exe</Image><!--Microsoft:Windows: HTML application executes scripts without IE protections | Credit @ion-storm [ https://en.wikipedia.org/wiki/HTML_Application ] -->
            <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msiexec.exe</Image> <!--Microsoft:Windows: Can install from http:// paths | Credit @vector-sec -->
            <Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">net.exe</Image> <!--Mitre T1018--><!--Mitre T1077--><!--Mitre T1087--><!--Mitre T1135--><!--Mitre T1069--><!--Mitre T1016--><!--Microsoft:Windows: "net use"/"net view" used by attackers to surveil and connect with file shares from command line | Credit @ion-storm -->
            <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">notepad.exe</Image> <!--Microsoft:Windows: [ https://blog.cobaltstrike.com/2013/08/08/why-is-notepad-exe-connecting-to-the-internet/ ] -->
            <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">powershell.exe</Image><!--Microsoft:Windows: PowerShell interface-->
            <Image name="technique_id=T1012,technique_name=Query Registry" condition="image">reg.exe</Image> <!--Mitre T1012--><!--Mitre T1112--><!--Microsoft:Windows: Remote Registry | Credit @ion-storm -->
            <Image name="technique_id=T1218,technique_name=Regsvr32" condition="image">regsvr32.exe</Image><!--Microsoft:Windows: [ https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html ] -->
            <Image name="technique_id=T1085,technique_name=Rundll32" condition="image">rundll32.exe</Image><!--Microsoft:Windows: [ https://blog.cobaltstrike.com/2016/07/22/why-is-rundll32-exe-connecting-to-the-internet/ ] -->
            <Image name="technique_id=T1031,technique_name=Modify Existing Service" condition="image">sc.exe</Image> <!--Microsoft:Windows: Remotely change Windows service settings from command line | Credit @ion-storm -->
            <Image name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="image">wmic.exe</Image> <!--T1047--><!--Mitre T1135--><!--Microsoft:WindowsManagementInstrumentation: Credit @Cyb3rOps [ https://gist.github.com/Neo23x0/a4b4af9481e01e749409 ] -->
            <Image name="technique_id=T1218,technique_name=Signed Script Proxy Execution" condition="image">wscript.exe</Image> <!--Microsoft:WindowsScriptingHost: | Credit @arekfurt -->
            <Image condition="image">driverquery.exe</Image> <!--Microsoft:Windows: Remote recognisance of system configuration, oudated/vulnerable drivers -->
            <Image condition="image">dsquery.exe</Image> <!--Microsoft: Query Active Directory -->
            <Image condition="image">hh.exe</Image> <!--Microsoft:Windows: HTML Help Executable, opens CHM files -->
            <Image condition="image">infDefaultInstall.exe</Image> <!--Microsoft: [ https://github.com/huntresslabs/evading-autoruns ] | Credit @KyleHanslovan -->
            <Image condition="image">javaw.exe</Image> <!--Java: Monitor usage of vulnerable application and init from JAR files -->
            <Image condition="image">javaws.exe</Image> <!--Java: Monitor usage of vulnerable application and init from JAR files -->
            <Image name="technique_id=T1031,technique_name=Modify Existing Service" condition="image">mmc.exe</Image> <!--Microsoft:Windows: -->
            <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image><!--Microsoft:Windows: [ https://www.hybrid-analysis.com/sample/a314f6106633fba4b70f9d6ddbee452e8f8f44a72117749c21243dc93c7ed3ac?environmentId=100 ] -->
            <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nbtstat.exe</Image> <!--Microsoft:Windows: NetBIOS statistics, attackers use to enumerate local network -->
            <Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">net1.exe</Image> <!--Mitre T1018--><!--Mitre T1077--><!--Mitre T1087--><!--Mitre T1135--><!--Mitre T1069--><!--Mitre T1016--><!--Microsoft:Windows: Launched by "net.exe", but it may not detect connections either -->
            <Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">nslookup.exe</Image> <!--Microsoft:Windows: Retrieve data over DNS -->
            <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qprocess.exe</Image> <!--Microsoft:Windows: [ https://www.first.org/resources/papers/conf2017/APT-Log-Analysis-Tracking-Attack-Tools-by-Audit-Policy-and-Sysmon.pdf ] -->
            <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qwinsta.exe</Image> <!--Microsoft:Windows: Remotely query login sessions on a server or workstation | Credit @ion-storm -->
            <Image name="technique_id=T1121,technique_name=Regsvcs/Regasm" condition="image">regsvcs.exe</Image> <!--Microsoft:Windows: [ https://www.hybrid-analysis.com/sample/3f94d7080e6c5b8f59eeecc3d44f7e817b31562caeba21d02ad705a0bfc63d67?environmentId=100 ] -->
            <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">rwinsta.exe</Image> <!--Microsoft:Windows: Disconnect remote sessions | Credit @ion-storm -->
            <Image name="technique_id=T1053,technique_name=Scheduled Task" condition="image">schtasks.exe</Image> <!--Microsoft:Windows: Command-line interface to local and remote tasks -->
            <Image name="technique_id=T1089,technique_name=Disabling Security Tools" condition="image">taskkill.exe</Image> <!--Microsoft:Windows: Kill processes, has remote ability -->
            <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">tasklist.exe</Image> <!--Microsoft:Windows: List processes, has remote ability -->
      <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">replace.exe</Image>
    </NetworkConnect>
</RuleGroup>
</EventFiltering>
</Sysmon>
```

**Example 2: Including Cloud Tools and Data Transfer Utilities**

Add these to your includes to capture potential exfiltration attempts:

```xml
<NetworkConnect onmatch="include">
  <!-- Cloud and Exfiltration Tools -->
  <Image condition="end with">cloudflared.exe</Image> <!-- Cloudflare tunnel - SSH/RDP tunneling -->
  <Image condition="end with">rclone.exe</Image> <!-- Cloud sync tool - data exfiltration -->
  <Image condition="end with">aws.exe</Image> <!-- AWS CLI -->
  <Image condition="end with">cmd5.exe</Image> <!-- AWS CLI S3 tool -->
  <Image condition="end with">gsutil.exe</Image> <!-- Google Cloud Storage -->
  <Image condition="end with">azcopy.exe</Image> <!-- Azure Storage -->
  <Image condition="contains">ngrok</Image> <!-- Tunneling service -->
  <Image condition="contains">curl.exe</Image> <!-- Data transfer utility -->
  <Image condition="contains">wget.exe</Image> <!-- Data transfer utility -->
</NetworkConnect>
```

What to Monitor and Investigate
--------------------------------

When reviewing network connection events, prioritize these patterns:

**1. Unexpected Process Making Connections**
* Any Windows system tool (cmd.exe, powershell.exe, wmic.exe) connecting to external IPs
* Compilation or scripting tools (msbuild.exe, cscript.exe, wscript.exe) making network requests
* Office applications (WINWORD.EXE, EXCEL.EXE) connecting to unusual destinations

**2. Cloud Tools from Unusual Locations**
* cloudflared.exe, rclone, or AWS tools running from temp directories or user downloads
* Cloud sync tools on servers or systems where they should not be installed
* Multiple cloud tools appearing on the same system in a short timeframe

**3. Lateral Movement Indicators**
* Workstation-to-workstation SMB (port 445) or RDP (port 3389) connections
* WinRM (port 5985/5986) connections between non-administrative systems
* Administrative tools connecting to multiple internal systems in sequence

**4. Geographic Anomalies**
* Connections to countries where your organization does not operate
* Connections to known high-risk geographic regions
* Sudden change in connection destinations for a process

**5. Volume Anomalies**
* Unusually large number of connections from a single process
* High-volume data transfer from a process that should not transfer significant data
* Beaconing patterns (regular, repeated connections at fixed intervals)

**6. Port and Protocol Anomalies**
* Connections on unusual ports (high-numbered ports, non-standard services)
* Protocols used in unexpected ways (DNS tunneling, ICMP tunneling)
* Standard ports used by non-standard processes

Common Exclusions (Use with Caution)
-------------------------------------

If using an exclusion-based approach, these are commonly excluded high-volume processes. However, implement these exclusions with specific criteria to prevent abuse:

**Browsers** - Exclude by full path and verify signed:
```xml
<Rule name="ChromeBrowser" groupRelation="and">
  <Image condition="begin with">C:\Program Files\Google\Chrome\Application\</Image>
  <Signed condition="is">true</Signed>
</Rule>
```

**System Updates** - Exclude Windows Update and known software updaters:
```xml
<Rule name="WindowsUpdate" groupRelation="and">
  <Image condition="is">C:\Windows\System32\svchost.exe</Image>
  <DestinationPort condition="is">443</DestinationPort>
  <DestinationHostname condition="contains">windowsupdate</DestinationHostname>
</Rule>
```

**NEVER Exclude These Without Additional Context:**
* PowerShell or cmd.exe making any external connections
* Cloudflared, rclone, or other tunneling/sync tools
* Administrative tools (wmic, sc, net, reg, etc.)
* Script hosts (cscript, wscript, mshta)
* Processes running from temp directories

Testing and Validation
-----------------------

After implementing network connection monitoring, validate effectiveness:

1. **Simulate C2 Traffic**: Use tools like Cobalt Strike or Metasploit in a lab to verify C2 beacon detection
2. **Test Cloud Exfiltration**: Upload a test file using rclone to verify detection
3. **Lateral Movement Simulation**: Test WinRM or PsExec between systems to ensure logging
4. **Baseline Normal Traffic**: Run your configuration for 1-2 weeks to understand typical volume and patterns
5. **Tune Exclusions**: Gradually add exclusions for verified benign high-volume traffic
6. **Monitor False Negative Risk**: Regularly test that exclusions have not created detection blind spots

Network connection monitoring, when properly configured, provides critical visibility into attacker communications, lateral movement, and data theft. The key is finding the balance between comprehensive coverage and manageable event volume through thoughtful inclusion and exclusion rules.
