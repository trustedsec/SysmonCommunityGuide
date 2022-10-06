File Block EXE
===========

On version 14.1 of Sysmon the capability to log and block when a process is deleting a file by overwriting its file blocks. Events will be loggedusing **EventID 27**. This event type is found under schema version 4.83.


![minifilter](./media/image36.png)

The minidriver inspect the action that is being taken to see if it is a file block overwrite and if the header of the file for the MZ DOS Executable header. Some common processes on system that perform actions that may generate some false positives are:

* svchost.exe
* dllhost.exe

Sysmon will not generate any alert on screen for the user once it takes the action. 


### Event information

The file delete event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that overwrote the fileblocks for the file

* **ProcessId**: Process ID used by the OS to identify the process that overwrote the fileblocks for the file.

* **Image**: File path of the process that overwrote the fileblocks for the file

* **TargetFilename**: Name of the file that is being deleted.

* **Hashes**: Full hash of the file with the algorithms in the HashType field.

* **IsExecutable**: If the file has a MZ header saying the file is an executable.



Here is a sample rule that removes some of thje false positives using full path and using a compound rule to make it harder to spoof by an attacker. 

```XML
<Sysmon schemaversion="4.83">
  <HashAlgorithms>sha1</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileBlockShredding onmatch="include">
        <Rule name="Wipe Action" groupRelation="and">
          <Image condition="is not">C:\WINDOWS\System32\svchost.exe</Image>
          <User condition="is not">NT AUTHORITY\LOCAL SERVICE</User>
        </Rule>
      </FileBlockShredding>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
