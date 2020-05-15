File Delete
===========

Via its filter driver, Sysmon can log the creation of files and information on what process is deleting of overwriting the file using **EventID 23**. This allows a defender to filter for:

* Dropper / stager that removes itself after execution (T1193 or T1064 and loads more) or attackers doing it manually

* Wiper software (T1485 and T1488)

* Ransomware (T1486)

![minifilter](./media/image36.png)

The file delete event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that deletec the file

* **ProcessId**: Process ID used by the OS to identify the process that deleted the file (child)

* **Image**: File path of the process that deleted the file

* **TargetFilename**: Name of the file that was deleted

**Hashes**: Full hash of the file with the algorithms in the HashType field. This is also the filename of the saved file in the ArchiveDirectory

* **Archived**: States whether the archival action was succesful

Example monitoring for script file creation by extension:

```XML
<Sysmon schemaversion="4.30">
<ArchiveDirectory>SysmonIsAwesome</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileCreate onmatch="include">
                <Rule groupRelation="or">
                    <TargetFilename condition="contains">\Downloads\</TargetFilename> <!--Download folder -->
                    <TargetFilename condition="end with">\Content.Outlook\</TargetFilename> <!--Outlook Temporary Internet files-->
                    <TargetFilename condition="end with">\AppData\Local\Temp\</TargetFilename>
                    <TargetFilename condition="end with">\AppData\Local\Microsoft\</TargetFilename> <!--Office temp files-->
                </Rule>

                <!-- File extension options -->
                <Rule groupRelation="or">
                    <TargetFilename condition="end with">.docm</TargetFilename>
                    <TargetFilename condition="end with">.pptm</TargetFilename>
                    <TargetFilename condition="end with">.xlsm</TargetFilename>
                    <TargetFilename condition="end with">.xlm</TargetFilename>
                    <TargetFilename condition="end with">.dotm</TargetFilename>
                    <TargetFilename condition="end with">.xltm</TargetFilename>
                    <TargetFilename condition="end with">.exe</TargetFilename>
                    <TargetFilename condition="end with">.js</TargetFilename>
                    <TargetFilename condition="end with">.hta</TargetFilename>
                    <TargetFilename condition="end with">.xls</TargetFilename>
                </Rule>
            </FileCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```