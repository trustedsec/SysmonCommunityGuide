Detection Engineering Fundamentals
===================================

Before diving into the technical details of Sysmon, it is important to understand the discipline that makes this tool truly valuable: detection engineering. Sysmon is not just a logging tool - it is a powerful instrument for detecting malicious behavior. However, like any instrument, its effectiveness depends on how skillfully it is used.

What is Detection Engineering?
-------------------------------

Detection engineering is the practice of designing, building, and maintaining systems that identify malicious or anomalous behavior in an environment. It sits at the intersection of threat intelligence, system knowledge, and data analysis. A detection engineer takes what we know about how attackers operate and translates that knowledge into concrete detection logic that can identify those behaviors when they occur.

Think of it this way: if attackers are constantly finding new ways to break into systems, detection engineers are constantly finding new ways to spot them doing it. This is not about waiting for antivirus signatures or relying solely on tools to protect you. Detection engineering is proactive - it means understanding your environment so well that you can recognize when something does not belong.

In the context of Sysmon, detection engineering means configuring the tool to capture the right information at the right time. Not everything that happens on a system is suspicious, and logging everything creates more problems than it solves. The skill lies in knowing what to capture and what to ignore.

Understanding Key Concepts
---------------------------

To work effectively with Sysmon as a detection engineer, you need to understand several important concepts:

**Signal-to-Noise Ratio**: This is perhaps the most critical concept. Signal refers to the meaningful data - the evidence of actual threats or important events. Noise refers to the normal, benign activity that clutters your logs. A good Sysmon configuration maximizes signal while minimizing noise. If your logs are 99% noise, you will miss the 1% that matters.

**True Positives**: These are legitimate detections - your system correctly identified actual malicious or anomalous activity. This is what we are trying to achieve.

**False Positives**: These occur when your detection logic flags normal, benign activity as suspicious. Too many false positives erode trust in your detections and waste valuable analyst time. Reducing false positives is one of the main goals of iterative configuration development.

**False Negatives**: These are the detections you missed - malicious activity that occurred but was not captured or flagged. False negatives are dangerous because they represent blind spots in your visibility. This happens when configurations are too restrictive or when exclusions are too broad.

**Baseline**: A baseline is your understanding of what normal looks like in your environment. You cannot identify anomalies until you know what normal behavior is. Baselining involves observing your systems over time to understand typical process execution, network connections, file operations, and other activities.

**MITRE ATT&CK Framework**: This is a knowledge base of adversary tactics and techniques based on real-world observations. It helps detection engineers understand what attackers do and, more importantly, what data sources can detect those actions. Sysmon is one of the most valuable data sources referenced in the ATT&CK framework, particularly for process monitoring.

Why Sysmon Configuration Matters
---------------------------------

Out of the box, Sysmon can be configured to log everything or log nothing. Neither extreme is useful. Logging everything creates an overwhelming volume of data that is expensive to store, slow to search, and impossible to analyze effectively. Logging nothing gives you no visibility.

The real value of Sysmon comes from thoughtful configuration. A well-designed configuration captures the behaviors that matter while filtering out the noise. This serves several critical purposes:

**Improved Detection Capability**: When your logs contain mostly meaningful data, it becomes much easier to identify actual threats. Analysts can focus on investigating real issues rather than wading through normal system activity.

**Reduced Storage Costs**: Security data can consume enormous amounts of storage, especially in large environments. Every event Sysmon logs must be stored, often for months or years for compliance reasons. Filtering out unnecessary events can reduce storage requirements by 80% or more in some cases.

**Better SIEM Performance**: Security Information and Event Management (SIEM) platforms are where Sysmon logs are typically sent for analysis. These systems have to index, search, and correlate millions of events. The more data you feed them, the slower they become and the more expensive they are to operate. A lean, well-filtered log stream keeps your SIEM responsive and cost-effective.

**Faster Investigations**: When an incident occurs, time matters. Analysts need to quickly understand what happened. If they have to sift through thousands of irrelevant events to find the few that matter, investigations slow down. Clean logs mean faster response times.

**Compliance and Retention**: Many organizations must retain security logs for regulatory compliance. The more you log, the more you must retain. Thoughtful configuration ensures you are retaining valuable evidence, not just storing noise.

Defense in Depth: Sysmon is Not Enough
---------------------------------------

One of the most critical principles in detection engineering is **defense in depth** - the concept that no single tool or data source should be your only line of defense. While Sysmon provides exceptional visibility into endpoint activity, it should **never be your only source of detection telemetry**.

**Why Multiple Data Sources Matter**:

Sysmon can be disabled, evaded, or bypassed by sophisticated attackers. If Sysmon is your only detection mechanism, a single point of failure exists. Mature detection programs use multiple, overlapping data sources that provide redundancy and complementary visibility.

**Windows Native Audit Logs**: Windows has built-in audit logging capabilities that should be enabled alongside Sysmon:

* **Security Event Log**: Provides authentication events (logon/logoff), privilege use, account management, and policy changes that Sysmon does not capture
  - Event ID 4688 (Process Creation) provides similar data to Sysmon Event ID 1, offering redundancy
  - Event ID 4624/4625 (Logon Success/Failure) are critical for detecting credential attacks and lateral movement
  - Event ID 4672 (Special Privileges Assigned) identifies privilege escalation
  - Event ID 4698-4702 (Scheduled Task Events) detect persistence mechanisms

* **System Event Log**: Captures service installations, system startups, and critical system events that can indicate tampering or persistence

* **Application Event Log**: May contain evidence of exploitation or abuse of applications

* **PowerShell Operational Logs**: Module logging, script block logging, and transcription provide deep visibility into PowerShell activity that complements Sysmon's process creation and script file monitoring

* **WMI-Activity/Operational**: Logs WMI activity including temporary subscriptions and events in the Root namespace that Sysmon does not capture (Sysmon only logs Root\Subscription)

**Why This Redundancy is Critical**:

1. **Attacker Evasion**: Attackers may target Sysmon specifically, attempting to stop the service or tamper with the driver. Windows audit logs are harder to disable without generating obvious alerts.

2. **Data Correlation**: Having multiple sources for the same event type (like process creation from both Sysmon and Windows Security Event ID 4688) allows you to detect tampering. If one source shows an event but the other does not, this is a strong indicator of log manipulation.

3. **Complementary Coverage**: Some activities are better captured by Windows audit logs than Sysmon. For example, Windows Security events provide detailed authentication information, privilege use, and account activity that Sysmon does not cover.

4. **Forensic Completeness**: During incident response, having multiple log sources provides a more complete timeline and can help validate findings. If logs conflict, it may indicate attacker activity.

5. **Detection Gaps**: As mentioned in the Sysmon chapter content, certain Sysmon event types have known limitations. For example, Sysmon only detects CreateRemoteThread() for process injection but not alternative APIs like NtCreateThreadEx(). Windows audit logs may capture related behaviors that Sysmon misses.

**Practical Implementation**:

For each detection use case, identify **all available data sources** that can provide visibility:

* **Lateral Movement Detection**: Combine Sysmon network connections (Event ID 3) with Windows logon events (4624/4625), network connection audit events, and firewall logs

* **Credential Access**: Use Sysmon process access events (Event ID 10) for LSASS dumping alongside Windows Security audit policy for sensitive privilege use and special logon events

* **Persistence Mechanisms**: Monitor with Sysmon registry events (12-14), file creation (11), service events (4), WMI events (19-21), AND Windows Security scheduled task events (4698-4702), service installation events (7045), and startup program modifications

* **Process Execution**: Log both Sysmon process creation (Event ID 1) and Windows Security process creation (Event ID 4688, requires audit policy and command line logging enabled)

**Best Practice**: When designing detection rules, always ask: "If Sysmon is compromised or bypassed, what other data sources can detect this behavior?" If the answer is "none," you have identified a dangerous single point of failure that needs additional data sources.

This layered approach ensures that even if an attacker disables Sysmon or finds ways to evade its monitoring, your detection capability remains intact through other telemetry sources. It also provides the redundancy needed to detect log tampering itself - a critical capability when responding to sophisticated adversaries.

The Iterative Configuration Process
------------------------------------

Creating an effective Sysmon configuration is not a one-time task. It is an iterative process that requires continuous refinement. Here is how mature detection engineering teams approach this:

**Phase 1 - Initial Deployment**: Start with a conservative configuration that captures key event types without exclusions. This gives you broad visibility to understand what is happening in your environment. Yes, it will be noisy, but that is expected at this stage. It is important to note that not all event types require the same approach. Some event types, like process tampering, driver loading, or raw disk access, are relatively infrequent in normal operations. For these low-volume event types, you can often log all occurrences without filtering and still maintain a good signal-to-noise ratio. Other event types, like process creation or network connections, occur constantly and require more aggressive filtering to be useful.

**Phase 2 - Baselining**: Observe the data being generated. What processes run regularly? What network connections are normal? What file operations happen as part of standard business activities? This phase typically takes 2-4 weeks, depending on your environment's complexity. Document what you learn. During this phase, you will quickly identify which event types generate high volumes of data and which remain relatively quiet.

**Phase 3 - Tuning**: Begin adding exclusions to filter out known-good activity for high-volume event types. This is where you reduce the noise. Be conservative - it is better to exclude too little at first than to exclude too much and create blind spots. Focus on high-volume, low-value events first. For low-volume event types that rarely occur during normal operations, you may decide to keep logging everything, using targeted include filters to ensure you capture the specific behaviors that matter most.

**Phase 4 - Validation**: After applying exclusions, validate that you have not created false negatives. Test your configuration against known attack techniques (in a safe, controlled manner). Can you still detect process injection? Do lateral movement attempts still generate logs? This phase is critical and often skipped, which leads to dangerous blind spots.

**Phase 5 - Monitoring and Refinement**: Even after deployment, continue to monitor the effectiveness of your configuration. As your environment changes - new applications are deployed, systems are upgraded, business processes evolve - your configuration must adapt. Schedule regular reviews, perhaps quarterly, to assess whether your configuration still meets your needs.

**Phase 6 - Threat Intelligence Integration**: As new attack techniques emerge or new vulnerabilities are disclosed, revisit your configuration. Can you detect this new technique? Do you need to modify exclusions to ensure visibility? This keeps your detections current and effective.

This iterative cycle never truly ends. Detection engineering is continuous improvement, not a project with a finish line.

Balancing Coverage and Performance
-----------------------------------

One of the hardest lessons for new detection engineers to learn is that you cannot log everything. There is a natural desire to maximize visibility by capturing all possible data. However, this creates real problems:

**System Performance Impact**: Sysmon runs at the kernel level and filters events in real-time. The more complex your configuration and the more events you capture, the more CPU resources Sysmon consumes. In extreme cases, poorly designed configurations can noticeably impact system performance.

**Network and Storage Costs**: Every event logged must be transmitted to your SIEM and stored. In a large environment, this can mean terabytes of data per day. At cloud storage prices, this becomes expensive quickly. Network bandwidth to transmit logs can also become a constraint.

**Analysis Paralysis**: Human analysts can only review so much data. If you generate millions of events per day, no team can keep up with reviewing them all. The more noise in your logs, the more likely real threats are to be missed.

The key is to focus on capturing outliers and anomalies, not normal behavior. You want to log the things that should not happen, not the things that happen all the time. This is especially important for high-volume event types like process creation and network connections. For lower-volume event types, the cost-benefit analysis is different - the overhead of logging all driver loads or all process tampering events is usually acceptable because these events are rare enough that they do not overwhelm your systems.

Reducing False Positives and False Negatives
---------------------------------------------

The goal of configuration tuning is to minimize both false positives and false negatives. These two objectives can be in tension - making your rules more specific to reduce false positives can create gaps that increase false negatives. The skill is finding the right balance.

**Reducing False Positives**: When you encounter false positives, resist the urge to immediately add broad exclusions. Instead, understand why the false positive occurred. Is this a legitimate business process you did not know about? Can you exclude it using multiple specific criteria rather than a broad rule? For example, instead of excluding all PowerShell execution, exclude PowerShell when it is launched by a specific management tool from a specific path with specific parameters.

**Preventing False Negatives**: False negatives often result from overly aggressive exclusions. When you exclude events, ask yourself: could an attacker abuse this exclusion? If you exclude a process by name only, an attacker can simply copy their malicious tool to use that same name. This is why multi-field exclusions are critical - use combinations of process path, command line parameters, hashes, and parent process information to create exclusions that are specific enough that they cannot be easily mimicked.

**Testing is Essential**: The only way to know if you have introduced false negatives is to test. Use frameworks like Atomic Red Team or tools like Caldera to safely simulate attack techniques in a test environment. Run your simulated attacks and verify that your Sysmon configuration still captures the activity. If an attack simulation does not generate the expected logs, you have found a false negative that needs to be addressed.

The Path Forward
----------------

As you work through the chapters that follow, keep these detection engineering principles in mind. Each event type will discuss not just what Sysmon can log, but why it matters for detection, how to configure it effectively, and what to watch out for.

Detection engineering is as much an art as a science. It requires understanding both the technical capabilities of your tools and the creative thinking of your adversaries. The goal is not perfection - you will never have zero false positives or zero false negatives. The goal is continuous improvement, building a detection capability that is effective, sustainable, and resilient.

Sysmon is one of the most powerful tools available for endpoint detection, but its power comes from how you use it. A thoughtfully designed, iteratively refined configuration tuned to your environment's needs will serve as the foundation for strong security monitoring and rapid incident response.

Now, let us explore how to put these principles into practice.
