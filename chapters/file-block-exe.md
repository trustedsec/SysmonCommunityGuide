File Block EXE
===========

On version 14.0 of Sysmon the capability to block the creation of executables by a process was added, this is the first event type where Sysmon takes a block action on a rule match. Sysmon relies on its filter driver, Sysmon can log the creation of files and information on what process is the the file using **EventID 27**. This event type is found under schema version 


![minifilter](./media/image36.png)

The minidriver inspect the header of the file for the MZ DOS Executable header. The file can be identified by the ASCII string "MZ" (hexadecimal: 4D 5A) at the beginning of the file (the "magic number"). "MZ" are the initials of Mark Zbikowski, one of the leading developers of MS-DOS. This header is included in DLLs, PE Files, COM executables and other executable types.

Sysmon will not generate any alert on screen for the user once it takes the action. 


### Event information

The file delete event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that attempted to create the file

* **ProcessId**: Process ID used by the OS to identify the process that attempted to create the file.

* **Image**: File path of the process that attempted to create the file

* **TargetFilename**: Name of the file that is being created.

**Hashes**: Full hash of the file with the algorithms in the HashType field. This is also the filename of the saved file in the ArchiveDirectory


Given the potential for this specific rule set to cause friction between a security team with users and other groups in the organization it is recommended to test before deploying. One recommendation is to use a file creation rule set to build a baseline of what executables are create where as part of normal day to day operations and then take that data to build a rule set that will minimize impact. 

A sample baseline ruleset can be:

```XML
<Sysmon schemaversion="4.82">
  <HashAlgorithms>sha1</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="File Creation" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename name="executables" condition="contains any">.dll;.exe</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Bellow is an example rule set that covers some of the most common scenarios where actors will drop executables using malicious documents, in emails, 

```XML
<Sysmon schemaversion="4.82">
  <HashAlgorithms>sha1</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="File Block Exe" groupRelation="or">
      <FileBlockExecutable onmatch="include">
        <!-- Primary -->
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">excel.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">winword.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">powerpnt.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">outlook.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">msaccess.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">mspub.exe</Image>
        
        <!-- Scripting Engines -->
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">powershell.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">mshta.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">cscript.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">wscript.exe</Image>

        <!-- LOLBins -->
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">certutil.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">esenutl.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">desktopimgdownldr.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">regsvr32.exe</Image>
        <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">Odbcconf.exe</Image>
      </FileBlockExecutable>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```
