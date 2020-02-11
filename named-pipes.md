Named Pipes
===========

A named pipe is a named, one-way or duplex pipe for communication
between the pipe server and one or more pipe clients. Each named pipe
has a unique name that distinguishes it from other named pipes in the
system\'s list of named objects. Pipe names are specified as
\\\\ServerName\\pipe\\PipeName when connection is local a "." would be
used as ServerName.

Named pipes are used for pivoting in several RATs/Implants to have SMB
connections between machines. Some tools will use named pipes to talk to
injected code in other processes.

Sysmon will generate a events

* **EventID 17** when a named pipe server is created.

* **EventID 18** when a client connects to a named piper server.

For named pipes there are 2 approaches that can be taken:

* Include all events and exclude known good.

* Include only known malicious actors.

The first approach requires more maintenance but in case of a breach
offers more value. The second one would be more targeted but this kind
of detection is better served with automation in the SIEM. Experienced
attackers normally avoid known Pipes to prevent breaking normal
operation of the system applications.

The process for PipeName values should be constant process.

![process](./media/image45.png)

Initial rule for collecting PipeEvent events

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

            <!--Include all PipeEvent events-->
            <PipeEvent onmatch="exclude">
            </PipeEvent>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

Collect unique PipeName field values for building filters

The fields for the Pipe Create Event are:

* **RuleName**: Name of rule that triggered the event.

* **EventType**: ***[CreatePipe]{.underline}***

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that created the pipe

* **ProcessId**: Process ID used by the OS to identify the process
    that created the pipe

* **PipeName**: Name of the pipe created

* **Image**: File path of the process that created the pipe

The fields for the Pipe Connect Event are:

* **RuleName**: Name of rule that triggered the event.

* **EventType**: ***[ConnectPipe]{.underline}***

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that connected the pipe

* **ProcessId**: Process ID used by the OS to identify the process
    that connected the pipe

* **PipeName**: Name of the pipe connected

* **Image**: File path of the process that connected the pipe

Example excluding known good Pipe Names

```XML
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="Exclude Filters for Named Pipes" groupRelation="or">
            <PipeEvent onmatch="exclude">
                <!-- Filter out known good named pipes -->
                <Rule groupRelation="or">
                    <!-- OS Pipes-->
                    <PipeName condition="is">\ntapvsrq</PipeName>
                    <PipeName condition="is">\srvsvc</PipeName>
                    <PipeName condition="is">\wkssvc</PipeName>
                    <PipeName condition="is">\lsass</PipeName>
                    <PipeName condition="is">\winreg</PipeName>
                    <PipeName condition="is">\spoolss</PipeName>
                    <PipeName condition="contains">Anonymous Pipe</PipeName>
                    <Image condition="is">c:\windows\system32\inetsrv\w3wp.exe</Image>

                    <!-- MSSQL Named Pipes-->
                    <PipeName condition="is">\SQLLocal\MSSQLSERVER</PipeName>
                    <PipeName condition="is">\SQLLocal\INSTANCE01</PipeName>
                    <PipeName condition="is">\SQLLocal\SQLEXPRESS</PipeName>
                    <PipeName condition="is">\SQLLocal\COMMVAULT</PipeName>
                    <PipeName condition="is">\SQLLocal\RTCLOCAL</PipeName>
                    <PipeName condition="is">\SQLLocal\RTC</PipeName>
                    <PipeName condition="is">\SQLLocal\TMSM</PipeName>
                    <Image condition="is">Program Files (x86)\Microsoft SQL Server\110\DTS\binn\dtexec.exe</Image>
                </Rule>
            </PipeEvent>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

One thing to consider is that Sysmon uses a minifilter just like the
file events. If any AV or EDR with a lower altitude number triggers
on a named pipe and blocks it, Sysmon will not log the event.
