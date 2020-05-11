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
                <!-- Detect Dangerous File Type Creation -->
                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=T1170,technique_name=Mshta" condition="end with">.hta</TargetFilename>
                </Rule>

                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=T1064,technique_name=Scripting" condition="end with">.bat</TargetFilename> <!--Batch scripting-->
                    <TargetFilename condition="end with">.cmd</TargetFilename> <!--Batch scripting | Credit @ion-storm -->
                    <TargetFilename condition="end with">.ps1</TargetFilename> <!--PowerShell-->
                    <TargetFilename condition="end with">.ps2</TargetFilename> <!--PowerShell-->
                    <TargetFilename condition="end with">.jse</TargetFilename> <!--Registry File-->
                    <TargetFilename condition="end with">.vb</TargetFilename> <!--VisualBasicScripting files-->
                    <TargetFilename condition="end with">.vbe</TargetFilename> <!--VisualBasicScripting files-->
                    <TargetFilename condition="end with">.vbs</TargetFilename> <!--VisualBasicScripting files-->
                </Rule>

                <!-- Detect ClickOnce -->
                <Rule groupRelation="or">
                    <TargetFilename name="ClickOnce File Execution" condition="end with">.application</TargetFilename>        <TargetFilename condition="end with">.appref-ms</TargetFilename>
                </Rule>

                <!-- MSBuild -->
                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=T1127,technique_name=Trusted Developer Utilities" condition="end with">.*proj</TargetFilename><!--Microsoft:MSBuild:Script More information: https://twitter.com/subTee/status/885919612969394177-->
                    <TargetFilename condition="end with">.sln</TargetFilename>
                </Rule>

                <!-- Macro File Creation -->
                <Rule groupRelation="or">
                    <TargetFilename name="Microsoft:Office: Macro" condition="end with">.docm</TargetFilename>
                    <TargetFilename condition="end with">.pptm</TargetFilename>
                    <TargetFilename condition="end with">.xlsm</TargetFilename>
                    <TargetFilename condition="end with">.xlm</TargetFilename>
                    <TargetFilename condition="end with">.dotm</TargetFilename>
                    <TargetFilename condition="end with">.xltm</TargetFilename>
                    <TargetFilename condition="end with">.potm</TargetFilename>
                    <TargetFilename condition="end with">.ppsm</TargetFilename>
                    <TargetFilename condition="end with">.sldm</TargetFilename>
                    <TargetFilename condition="end with">.xlam</TargetFilename>
                    <TargetFilename condition="end with">.xla</TargetFilename>
                </Rule>
            </FileCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
