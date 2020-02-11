File Create
===========

Via its filter driver, Sysmon can log the creation of files and information on what process is creating the file using **EventID 11**. This allows defenders to filter for:

* Dropping of files for later execution (PowerShell, Office Apps, certutil.exe)

* Modification of system configurations (Scheduled Tasks, WMI)

* Detection of malicious behaviors that create temporary or log files (.Net compile and run, DotNet2JS)

Since AV minifilters load before Sysmon (due to their lower altitude number range), if an AV or EDR minifilter driver detects a malicious file and blocks it writing to disk, Sysmon will not log the event.

![minifilter](./media/image36.png)

The file creation event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that created the file

* **ProcessId**: Process ID used by the OS to identify the process that created the file (child)

* **Image**: File path of the process that created the file

* **TargetFilename**: Name of the file that was created

* **CreationUtcTime**: File creation time

Example monitoring for script file creation by extension:

```XML
<Sysmon schemaversion="4.22">
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

                <!-- DotNettoJS UsageLog -->
                <Rule groupRelation="or">
                    <TargetFilename name="technique_id=1218,technique_name=DotnettoJs" condition="contains">AppData\Local\Microsoft\CLR_v2.0\UsageLogs\</TargetFilename><!--Dotnet v2 binary started-->
                    <TargetFilename condition="end with">\UsageLogs\cscript.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\wscript.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\wmic.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\mshta.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\svchost.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\regsvr32.exe.log</TargetFilename>
                    <TargetFilename condition="end with">\UsageLogs\rundll32.exe.log</TargetFilename>
                </Rule>
            </FileCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
