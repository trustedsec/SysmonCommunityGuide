DNS Query
=========

Sysmon will log **EventID 22** for DNS queries made using the Windows DnsQuery_* API calls in **dnsapi.dll**. DNS query logging provides valuable detection capabilities for command and control communication, data exfiltration via DNS tunneling, and discovery activity. However, volume can be **moderate to high** depending on configuration, requiring careful filtering.

Detection Value and Use Cases
------------------------------

DNS query monitoring provides visibility into:

**Command and Control (C2) Detection**: Attackers must resolve domain names to connect to C2 infrastructure. DNS logs help detect:
* Newly registered domains (often used for C2)
* Domain generation algorithms (DGA) producing random-looking domains
* Fast-flux DNS (rapidly changing IP addresses)
* Connections to known malicious domains

**Data Exfiltration via DNS Tunneling**: Attackers encode data in DNS queries to bypass network controls:
* Unusually long DNS queries (data encoded in subdomain)
* High volume of DNS queries to the same domain
* Suspicious TXT or other record type queries

**Discovery and Reconnaissance**: Attackers query DNS during reconnaissance:
* Internal domain enumeration
* Checking for internet connectivity
* Identifying security controls

**MITRE ATT&CK Mapping**:
* **T1071.004 - Application Layer Protocol: DNS** - C2 over DNS
* **T1568 - Dynamic Resolution** - Domain generation algorithms
* **T1048.003 - Exfiltration Over Alternative Protocol: DNS** - DNS tunneling
* **T1590 - Gather Victim Network Information** - DNS reconnaissance

Important Technical Limitations
--------------------------------

**Windows API Dependency**: Sysmon only logs DNS queries made through the Windows DnsQuery_* API calls in dnsapi.dll. This is supported on Windows 8.1 and above using ETW (Event Tracing for Windows) functionality.

**What is NOT logged:**
* Programs that perform custom DNS resolution (bypassing Windows APIs)
* Direct queries to DNS servers using raw sockets
* DNS queries from some network security tools
* Queries from applications using alternative DNS libraries

This means DNS query logging provides good coverage for most Windows applications but is not comprehensive for all DNS activity on a system.

Volume Characteristics and Configuration Strategy
--------------------------------------------------

DNS query volume varies significantly:
* **High-volume environments**: Web browsing, cloud applications, and SaaS usage generate thousands of queries per hour
* **Lower-volume environments**: Servers or systems with limited internet access may have manageable DNS query counts

**Two configuration approaches:**

**Approach 1 - Exclusion-Based (Recommended)**: Log all DNS queries but exclude high-volume, known-good domains (Microsoft, Google, CDNs). This provides good visibility while keeping volume manageable.

**Approach 2 - Targeted Includes**: Only log queries from specific suspicious processes or to specific suspicious domains. This minimizes volume but may miss novel threats.

The fields for the event are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that made the DNS query

* **ProcessId**: Process ID of the process that made the DNS query

* **QueryName**: DNS name that was queries

* **QueryStatus**: Query result status code

* **QueryResults**: Query results

* **Image**: File path of the process that made the DNS query
What to Investigate
--------------------

When reviewing DNS query events, prioritize:

**1. DGA-Like Domains**: Random-looking, algorithmically generated domain names (long strings of consonants, numeric patterns)

**2. Newly Registered Domains**: Domains registered within the last 30-90 days (cross-reference with threat intelligence)

**3. Unusual TLDs**: Uncommon top-level domains often abused for C2 (.tk, .pw, .cc, etc.)

**4. Long DNS Queries**: QueryName exceeding 50-100 characters may indicate DNS tunneling

**5. High Query Volume to Single Domain**: Many queries to the same domain in short timeframe (potential tunneling or beaconing)

**6. DNS Queries from Unusual Processes**: System utilities, Office applications, or scripts making DNS queries

**7. Known Malicious Domains**: Match against threat intelligence feeds

Configuration Best Practices
-----------------------------

Exclude known benign, high-volume destinations to focus on unknown or suspicious domains. This is a high-volume event type, so experimentation and environment-specific tuning is essential.

**Community Resources**: Excellent examples can be found at https://github.com/olafhartong/sysmon-modular/tree/master/22_dns_query

Example configuration excluding known update and telemetry domains:

```xml
<Sysmon schemaversion="4.22">
   <!-- special thanks to @SwiftOnSecurity for this -->
   <HashAlgorithms>*</HashAlgorithms>
   <CheckRevocation/>
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
      <!-- Browser Update Domains-->

      <!--Mozilla-->
      <QueryName condition="end with">
         .mozaws.net
      </QueryName>
      <QueryName condition="end with">
         .mozilla.com
      </QueryName>
      <QueryName condition="end with">
         .mozilla.net
      </QueryName>
      <QueryName condition="end with">
         .mozilla.org
      </QueryName>
         
      <!--Google-->
      <QueryName condition="is">
         clients1.google.com
      </QueryName>
      <QueryName condition="is">
         clients2.google.com
      </QueryName>
      <QueryName condition="is">
         clients3.google.com
      </QueryName>
      <QueryName condition="is">
         clients4.google.com
      </QueryName>
      <QueryName condition="is">
         clients5.google.com
      </QueryName>
      <QueryName condition="is">
         clients6.google.com
      </QueryName>
      <QueryName condition="is">
         safebrowsing.googleapis.com
      </QueryName>
         
      <!-- Microsoft Domains -->
      <!--Microsoft: Doesn't appear to host customer content or subdomains-->
      <QueryName condition="end with">
         -pushp.svc.ms
      </QueryName> 
      <QueryName condition="end with">
         .b-msedge.net
      </QueryName> 
      <!-- Microsoft | Microsoft default exclusion -->
      <QueryName condition="end with">
         .bing.com
      </QueryName> 
      <QueryName condition="end with">
         .hotmail.com
      </QueryName>
      <QueryName condition="end with">
         .live.com
      </QueryName>
      <QueryName condition="end with">
         .live.net
      </QueryName>
      <QueryName condition="end with">
         .s-microsoft.com
      </QueryName>
      <QueryName condition="end with">
         .microsoft.com
      </QueryName>
      <QueryName condition="end with">
         .microsoftonline.com
      </QueryName>
      <QueryName condition="end with">
         .microsoftstore.com
      </QueryName>
      <QueryName condition="end with">
         .ms-acdc.office.com
      </QueryName> 
      <QueryName condition="end with">
         .msedge.net
      </QueryName>
      <QueryName condition="end with">
         .msn.com
      </QueryName>
      <QueryName condition="end with">
         .msocdn.com
      </QueryName>
      <QueryName condition="end with">
         .skype.com
      </QueryName>
      <QueryName condition="end with">
        .skype.net
      </QueryName>
      <QueryName condition="end with">
         .windows.com
      </QueryName>
      <QueryName condition="end with">
         .windows.net.nsatc.net
      </QueryName>
      <QueryName condition="end with">
         .windowsupdate.com
      </QueryName>
      <QueryName condition="end with">
         .xboxlive.com
      </QueryName>
      <QueryName condition="is">
         login.windows.net
      </QueryName>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
