Process Termination
-------------------

Symon will log an **EventID 5** when a process terminates. By logging
process termination events allow for calculating duration of operation
of a process by comparing the times with process creation. Process
termination also allows when co-related with shutdown and start events
if a process may have been terminated by an attacker.

The process termination fields are:

* **RuleName** -- Rule name for which the event triggered.

* **UtcTime** - Time in UTC when event was created

* **ProcessGuid** - Process Guid of the process that terminated

* **ProcessId** - Process ID used by the OS to identify the process
    that terminated

* **Image** - File path of the executable of the process that
    terminated