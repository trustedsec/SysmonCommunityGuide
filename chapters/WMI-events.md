WMI Events
==========

Sysmon will log **EventID 19** (WmiEventFilter), **EventID 20** (WmiEventConsumer), and **EventID 21** (WmiEventConsumerToFilter) for Windows Management Instrumentation (WMI) event subscriptions. WMI event monitoring is a **low-volume, extremely high-value event type** that should almost always log all occurrences. WMI persistence is a sophisticated technique heavily used by advanced attackers and rarely by legitimate software outside of enterprise management tools.

Detection Value and Why It Matters
-----------------------------------

WMI events have been used legitimately for over a decade by vendors and enterprise users to automate actions on systems. However, attackers leverage the same capability for persistence and automation, making this a critical detection opportunity.

WMI persistence is attractive to attackers because:

**Fileless Persistence**: WMI event subscriptions are stored in the WMI repository (CIM database), not as files on disk. This makes them harder to detect with traditional file-based security tools and harder to find during incident response.

**SYSTEM-Level Execution**: Permanent WMI event subscriptions always run as SYSTEM, providing attackers with the highest privileges regardless of the account used to create the subscription.

**Survives Reboots**: Permanent subscriptions persist across system restarts, providing reliable long-term persistence.

**Rare in Normal Environments**: Outside of enterprise system management tools (SCCM, monitoring software), WMI event subscriptions are uncommon, making detections high-fidelity.

**APT Tradecraft**: WMI persistence has been documented in attacks by APT28, APT29, and numerous other sophisticated threat actors.

**MITRE ATT&CK Mapping**:
* **T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription** - Primary technique
* **T1047 - Windows Management Instrumentation** - General WMI abuse

How WMI Event Subscriptions Work
----------------------------------

WMI events occur when specific Event Class instances are created or modified in the WMI Model. An attacker can monitor for these events and trigger actions when they occur by using subscriptions.

There are two types of WMI Event Subscriptions:

-   **Temporary** - Subscription is active as long as the process that created
    the subscription is active (They run under the privilege of the process)

-   **Permanent** - Subscription is stored in the CIM Database and is active
    until removed from it (They always run as SYSTEM)

All event subscriptions have three components:

-   **Filter** - WQL Query for the events we want

-   **Consumer** - An action to take upon triggering the filter

-   **Binding** - Registers a filter to a consumer

The filter and consumer are created individually and then registered together.
The actions that Sysmon filters on are those for permanent events. Sysmon will
only log **ActiveScript** and **CommandLine** consumers since these are the ones
abused by attackers.

Why This is Low-Volume
-----------------------

WMI event subscriptions are extremely rare in typical environments:
* Most systems have zero WMI event subscriptions
* Legitimate uses are limited to enterprise management tools (SCCM, monitoring agents)
* Typical environments generate 0-5 WMI events per month, often zero
* Any activity is noteworthy and warrants review

This extremely low volume makes WMI event monitoring ideal for a **log-all approach** with minimal or no exclusions.

What to Investigate
--------------------

When reviewing WMI event logs, **investigate every occurrence** unless it's from verified enterprise management software:

**1. All Three Event IDs Together**
* WMI persistence requires all three components: Filter (ID 19), Consumer (ID 20), and Binding (ID 21)
* Look for these event IDs occurring close together in time
* A complete attack chain will have all three

**2. Consumer Destination (Most Critical)**
* The **Destination** field in EventID 20 shows what command or script will execute
* Look for:
  - PowerShell commands, especially encoded commands
  - CMD.exe with suspicious arguments
  - Script execution (cscript.exe, wscript.exe)
  - Downloading or executing files from the internet
  - Credential dumping tools or suspicious utilities

**3. Suspicious Filter Queries**
* EventID 19 shows the WQL query that triggers the consumer
* Common attacker patterns:
  - Triggers on system startup: `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'`
  - Triggers on user logon events
  - Triggers on specific process starts
  - Time-based triggers for periodic execution

**4. Unusual User Context**
* WMI subscriptions require administrator privileges to create
* Investigate subscriptions created by:
  - Non-administrative user accounts (shouldn't be possible)
  - Service accounts not associated with management tools
  - Recently compromised accounts
  - Accounts with suspicious recent activity

**5. Namespace Analysis**
* Most legitimate WMI subscriptions use `Root\Subscription` namespace
* **Important Limitation**: Sysmon only logs subscriptions in `Root\Subscription`, not `Root` namespace
* Attackers aware of this may use the `Root` namespace to evade detection
* This gap is covered by Windows native WMI-Activity/Operational logs (EventID 5861)

**6. Correlation with Other Events**
* WMI subscription creation shortly after:
  - Initial compromise indicators
  - Suspicious PowerShell or CMD execution
  - Lateral movement activity
  - Privilege escalation

Event Fields and Structure
---------------------------

Fields for the Filter creation, modification, or deletion are:

-   **RuleName**: Rule name for filter

-   **EventType**: Will always be *WmiFilterEvent*

-   **UtcTime**: Time event happened

-   **Operation**: Created, modified or deleted

-   **User**: User that performed the action

-   **EventNamespace**: WMI Namespace where object was created

-   **Name**: Name of the filter

-   **Query**: Query defined for the filter

The fields for Consumer creation, modification, or deletion are:

-   **RuleName**: Rule name for filter

-   **EventType**: Will always be *WmiConsumerEvent*

-   **UtcTime**: Time event happened

-   **Operation**: Created, modified, or deleted

-   **User**: User that performed the action

-   **Name**: Name of the consumer

-   **Type**: Type of consumer

-   **Destination**: Command or Script being executed

The fields for filter to consumer binding are:

-   **RuleName**: Rule name for filter

-   **EventType**: Will always be *WmiBindingEvent*

-   **UtcTime**: Time event happened

-   **Operation**: Created, modified, or deleted

-   **User**: User that performed the action

-   **Consumer**: Consumer path in the CIM Database

-   **Filter**: Filter path in the CIM Database

When a Permanent Event Subscription is created, an EventID **5861** in
**Microsoft-Windows-WMI-Activity/Operational** is created in **Windows 2012 R2,
Windows 2016,** and **Windows 10 Pro/Enterprise**.

The event includes the Query and Consumer object information for the
subscription in its data.

![Bind Event](media/image62.png)

Configuration: Log All (Recommended)
-------------------------------------

Given the extremely low volume and extremely high detection value, the recommended configuration is simple - **log everything**:

```XML
<Sysmon schemaversion="4.22">
   <HashAlgorithms>*</HashAlgorithms>
   <CheckRevocation/>
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <WmiEvent onmatch="exclude">
            <!-- Log all WMI events - volume is extremely low -->
            <!-- Only exclude specific enterprise management tools if needed -->
         </WmiEvent>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
```

**Optional Exclusions**: In environments with enterprise management software (SCCM, monitoring agents), you may choose to exclude specific known-good subscriptions. However, given the low volume, it's often better to log everything and filter in your SIEM.

If you must exclude, use the **Name** field to exclude specific subscription names after verification:

```XML
<WmiEvent onmatch="exclude">
   <!-- Example: Exclude verified SCCM WMI subscriptions -->
   <Operation condition="is">Created</Operation>
   <Consumer condition="contains">SCNotification</Consumer>
</WmiEvent>
```

Important Limitations and Complementary Logging
------------------------------------------------

**Sysmon Gap**: Sysmon will not capture components of permanent events created in the **Root** namespace, only under **Root/Subscription**. Attackers aware of this limitation may use the `Root` namespace to evade detection.

**Recommended Complementary Logging**: Enable Windows native **WMI-Activity/Operational** logs (EventID 5861) which do capture events created in the **Root** namespace. This provides:
* Coverage for Root namespace subscriptions (fills Sysmon gap)
* Temporary event subscriptions (not logged by Sysmon)
* WMI query errors (useful for detecting reconnaissance)
* Provider loading activity

**Detection Strategy**: Use both Sysmon WMI events and native Windows WMI-Activity logs for comprehensive coverage. The combination ensures attackers cannot evade detection by using alternative namespaces or temporary subscriptions.
