Installation and Configuration
=========================

Sysmon installation and configuration can be done via the command line. When Sysmon is downloaded from Microsoft, the zip file will contain two command line versions of the tool:

* **Sysmon.exe** - x86 and x64 version.

* **Sysmon64.exe** - 64bit only version.

When using the tool, any errors will result in an error message and help information with basic switches. To see only the help information for the tool, the **-?** switch parameter is used. This help information will include:

* Parameter sets for installation, configuration, and uninstall

* Common command line parameters.

* General notes on how the tool works and further details on how to get more help information.

The parameters of the tool and the structure of the XML configuration file are defined in the tool Schema. This schema can be printed using the **-s "PrintSchema"** parameter; if no schema version is provided, it will print the default schema.

The tool can be run in 4 main modes; 3 of them are shown in the help message:

* **Install** - Install the driver, manifest and service on the host.

* **Configure** - Parses a given configuration file or command line parameters to generate a configuration that is stored in the registry.

* **Uninstall** - Removes the driver and service from the host.

The semi-hidden and undocumented method is Debug, in which a specified configuration is parsed, and live events are shown in the console.

Install
-------

The key parameter that initiates the installation mode of Sysmon is the **-i** switch. The installation process will be as follows:

* Decompresses and saves driver and copy of itself in to **%systemroot%**

* Registers event log manifest

* Creates a service

* Enables a default configuration (ProcessCreation, ProcessTermination, DriverLoad , FileCreationTimeChanged, SHA1 for Images) if no configuration file is passed using the **-c \<configuration file\>** parameter

The Installation process allows for some obfuscation:

* Driver name can be changed

* Service name can be changed

* Sysmon binary name can be renamed.

These obfuscation changes will also affect registry paths for the driver and processes service keys. All of the obfuscation methods are part of the installation option set.

The installation options are:

* Default -- Driver is installed and named SysmonDrv and service Sysmon

```shell
sysmon.exe --i --accepteula

```

* Renamed Driver -- The driver file and registry entry are renamed. Name has an 8-character limit.

```shell
sysmon.exe -i -d <drivername>
```

* Renamed Service -- The executable name defines the service name.

```shell
<renamed sysmon>.exe -i -d <drivername>
```

The installation process on a x64 system with the binary named sysmon.exe that is intended to work across x64 and x86 architectures is shown below. This is important since some of the actions may cause confusion or trigger alerts on monitoring systems.

One important thing to keep in mind when obfuscating the driver name and service name is that certain characteristics remain the same.

* Service description remains the same. (This can be modified post-install.)

* Driver Altitude number remains the same.

* The eventlog remains the same so as to not break collection from SIEM products.

Process for x86
---------------

![x86 bit insall process](./media/image6.png)

x64 Process
-----------

![x64 install process](./media/image7.png)

Sysmon will create 2 registry keys to define the services for its operation under ***HKLM\\SYSTEM\\CurrentControlSet\\Services***

* Sysmon - Service that talks to the driver and performs the filtering action. It is named with the same name as the Sysmon executable.

* SysmonDrv - Kernel Driver Service, this service loads the Sysmon driver with an altitude number of 385201

The settings for each service are:

Main Service:

* Name: **Name of the executable (default Sysmon or Sysmon64)**

* LogOn: **Local System**

* Description: **System Monitor service**

* Startup: **Automatic**

* ImagePath: **%windir%\\\<exe name\>**

Driver Service:

* Name: **SysmonDrv unless --d \<name\> is**

* LogOn: **Local System**

* Description: **System Monitor driver**

* Startup: **Automatic**

* ImagePath: **\<driver name\>.sys**

Installation with Configuration
-------------------------------
An XML configuration file can be passed during installation if an initial configuration needs to be set. This is the preferred method for production systems since a configuration file can cover all types and logic. The most used method is to pass a configuration file using the **-c \<config file\>** parameter.

```shell
sysmon.exe -i --accepteula -c <config file>
```

If the configuration specifies a archive folder using the ```<ArchiveDirectory>``` element the **-a \<archive folder\>** needs to be specified in the command line so that Sysmon can create the folder and set the proper permissions for version 11.0 of Sysmon, for version 11.1 the parameter was removed and now it is configured via the configuration file. If the folder is not present and even if specified Sysmon will create a folder named **Sysmon** instead and use that folder to archive the deleted files. 

We can control the hashing algorithm used for events that hash images and we can control checking of revocation of signatures.

The hashing algorithm or combination of them can be specified with the **-h \<sha1\|sha2\|md5\|imphash\|\*\>** The specified algorithms will be used to hash all images.

```shell
sysmon.exe -i -c -h <sha1|sha2|md5|imphash\|*>
```

We can specify checking to see if certificates are revoked using the -r parameter.

```shell
sysmon.exe -i -c -r

```

SSome basic filtering can be done also from the command line. Only filtering by process name can be done for NetworkConnect, ImageLoad, and ProcessAccess via the command line.

* **NetworkConnect** - Track network connections.

```shell
sysmon.exe -i -c -n [<process,...>]
```

* **ImageLoad** - DLL loading by processes.

```shell
sysmon.exe -i -c -l [<process,...>]
```

* **ProcessAccess** - Processes whose memory is accessed.

```shell
sysmon.exe -i -c -k [<process,...>]
```

Uninstall
---------

To uninstall Sysmon, a binary with the same name as the main service, if renamed, has to be run with the **-u** switch parameter.

```shell
sysmon.exe -u
```

When executed the command will run a series of steps to uninstall the service, driver and remove files for the tool.

![Uninstall Process](./media/image8.png)

There is an undocumented value that can be passed to the **-u** parameter of **"force"** to force the removal of the services even if a stop was not possible.

```shell
sysmon.exe -u force
```

Installation Best Practice
--------------------------

Installation best practices that can be followed to aid and minimize risk when deploying the Sysmon tool include:

* Keep a repository of Sysmon versions archived; Microsoft does not provide older versions for download.

* Sysmon is very dependent on the version of the binary for its configuration. The install/upgrade script should check the binary version for:

  * Upgrade

  * Version for applying initial config

* If a GPO is used to push scheduled tasks for upgrades or to push configuration, use a WMI filter to target the specific version that was tested. Example:

```sql
SELECT * FROM CIM_Datafile WHERE (Name="c:\\Windows\\Sysmon64.exe" OR Name="c:\\Windows\\Sysmon.exe") AND version="10.0.4.1"
```

* Check file versions they don't match release versioning.

* It is better to not push configuration as an XML that gets run from a share or dropped on disk with a scheduled task:

  * Credentials are left that can be recovered via DPAPI for deleted scheduled tasks.

  * The file can be read more easily by an attacker if controls are not properly placed

  * There is a higher chance of human error

  * Better to push values via GPO or other methods with file version checking.

