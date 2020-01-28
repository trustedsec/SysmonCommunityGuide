**WMI Events**

WMI events, both temporary and permanent (survive a reboot), have been used for
over a decade by vendors and enterprise users to automate actions on systems.
Attackers leverage events in the same manner for automating actions and for
persistence. Attackers will create or modify existing event components (APT 28,
29) on systems for which they gain administrator privilege. WMI events are those
events that happen when a specific Event Class instance is created or they are
modified in the WMI Model.

An attacker can monitor (and take certain actions) when these events occur by
using subscriptions that monitor for them.

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

![](media/b3a9f4a4ee246fb3091d0cd33e4206ce.png)

It is recommended to log all instances of this event type.
