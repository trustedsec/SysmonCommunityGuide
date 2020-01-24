Registry Actions
================

Sysmon has the capability to monitor for 3 major actions against
Registry

* **EventID 12** - Registry object added or deleted

* **EventID 13** - Registry value set

* **EventID 14** - Registry object renamed

The Windows Registry has been a source of information gathering,
persistence, storage and configuration control for attackers since its
wider use introduction in Windows NT 4.0/Windows 95.

Sysmon uses abbreviated versions of Registry root key names, with the
following mappings:

|**Key name**                                  |**Abbreviation**                |
|---------------------------------------------|---------------------------------
| HKEY\_LOCAL\_MACHINE                          |HKLM|
| HKEY\_USERS                                   |HKU|
| HKEY\_LOCAL\_MACHINE\\System\\ControlSet00x   |HKLM\\System\\CurrentControlSet|
| HKEY\_LOCAL\_MACHINE\\Classes                 |HKCR|

Registry Add/Delete Fields:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **EventType**: CreateKey or DeleteKey

* **ProcessGuid**: Process Guid of the process that created or deleted
    a registry key

* **ProcessId**: Process ID used by the OS to identify the process
    that created or deleted a registry key

* **Image**: File path of the process that created or deleted a
    registry key

* **TargetObject**: Complete path of the registry key

Registry Set Value Fields:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **EventType**: SetValue

* **ProcessGuid**: Process Guid of the process that modified a
    registry value

* **ProcessId**: Process ID used by the OS to identify the process
    that that modified a registry value

* **Image**: File path of the process that that modified a registry
    value

* **TargetObject**: Complete path of the modified registry key

* **Details**: Details added to the registry key

Registry Rename Fields:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **EventType**: RenameKey

* **ProcessGuid**: Process Guid of the process that renamed a registry
    value and key

* **ProcessId**: Process ID used by the OS to identify the process
    that renamed a registry value and key

* **Image**: File path of the process that renamed a registry value
    and key

* **TargetObject**: Complete path of the renamed registry key

* **NewName**: New name of the registry key

This event type is better used in a targeted manner given the size of
the registry and how it is used by a multitude of processes on a daily
basis in Windows.

In registry events, the value name is appended to the full key path with
a \"\\\" delimiter.

Default key values are named \"\\(Default)\"

When filtering for keys or values in HKCU use **contains** or **end
with** when filtering against **TargetObject** since the SID of the user
is appended after the Hive name

![HKCU Test](./media/image51.png)

![HKCU Test Event](./media/image52.png)

Since the value name is appended when specifying a registry path in
**TargetObject** where we also want to catch modification of values
under the key the **contains** operator is better suited than **ends
with.** For value events the **Detail** element of the event will
contain the type of value.

Sysmon does not log the actual value being set nor a previous and new
one being modified.

![HCU Value Event](./media/image53.png)

Example of monitoring some AutoRun locations

```xml
<Sysmon schemaversion="4.22">
   <EventFiltering>
 <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject name="technique_id=T1060,technique_name=Registry Run Keys / Start Folder" condition="contains">\CurrentVersion\Run</TargetObject><!--Microsoft:Windows: Run keys, incld RunOnce, RunOnceEx, RunServices, RunServicesOnce [Also covers terminal server] -->
        <TargetObject condition="contains">\Group Policy\Scripts</TargetObject> <!--Microsoft:Windows: Group policy scripts-->
        <TargetObject name="technique_id=T1037,technique_name=Logon Scripts" condition="contains">\Windows\System\Scripts</TargetObject> <!--Microsoft:Windows: Logon, Loggoff, Shutdown-->
        <TargetObject name="technique_id=T1060,technique_name=Registry Run Keys / Start Folder" condition="contains">\Policies\Explorer\Run</TargetObject><!--Microsoft:Windows -->
        <TargetObject condition="end with">\ServiceDll</TargetObject> <!--Microsoft:Windows: Points to a service's DLL [ https://blog.cylance.com/windows-registry-persistence-part-1-introduction-attack-phases-and-windows-services ] -->
        <TargetObject condition="end with">\ImagePath</TargetObject> <!--Microsoft:Windows: Points to a service's EXE [ https://github.com/crypsisgroup/Splunkmon/blob/master/sysmon.cfg ] -->
        <TargetObject condition="end with">\Start</TargetObject> <!--Microsoft:Windows: Services start mode changes (Disabled, Automatically, Manual)-->
        <TargetObject name="technique_id=T1004,technique_name=Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify</TargetObject><!--Microsoft:Windows: Autorun location [ https://www.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order ] -->
        <TargetObject name="technique_id=T1004,technique_name=Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject> <!--Microsoft:Windows: Autorun location [ https://www.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order ] -->
        <TargetObject name="technique_id=T1004,technique_name=Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
        <TargetObject condition="begin with">HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32</TargetObject> <!--Microsoft:Windows: Legacy driver loading | Credit @ion-storm -->
        <TargetObject name="technique_id=T1060,technique_name=Registry Run Keys / Start Folder" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute</TargetObject> <!--Microsoft:Windows: Autorun | Credit @ion-storm | [ https://www.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order ] -->
        <TargetObject name="technique_id=T1042,technique_name=Change Default File Association" condition="contains">\Explorer\FileExts</TargetObject><!--Microsoft:Windows: Changes to file extension mapping-->
        <TargetObject condition="contains">\shell\install\command</TargetObject> <!--Microsoft:Windows: Sensitive subkey under file associations and CLSID that map to launch command-->
        <TargetObject condition="contains">\shell\open\command</TargetObject> <!--Microsoft:Windows: Sensitive subkey under file associations and CLSID that map to launch command-->
        <TargetObject condition="contains">\shell\open\ddeexec</TargetObject> <!--Microsoft:Windows: Sensitive subkey under file associations and CLSID that map to launch command-->
        <TargetObject name="technique_id=T1060,technique_name=Registry Run Keys / Start Folder" condition="contains">Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup</TargetObject>
    </RegistryEvent>
</RuleGroup>
</EventFiltering>
</Sysmon>
```
