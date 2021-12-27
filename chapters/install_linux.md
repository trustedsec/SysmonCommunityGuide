Install and Configuration
=========================

Installation under Linux varies given that each Linux distribution and even version of each differ slightly in the steps to install the packages for sysinternalsEBPF and sysmonforlinux. The package installation steps for each distribution and is maintained in github at <https://github.com/Sysinternals/SysmonForLinux/blob/main/INSTALL.md>. The solution can be compiled and installed from source but it is not recommended for a production environment since it will add more complexity in the tracking of versions of dependencies and also introduced other packages that can be abused by an attacker if they gain access tto the system.

The package installation process will create a sysmon elf binary as /usr/bin/sysmon this binary will be used to install and configure the service.

When using the tool, any errors will result in an error message and help information with basic switches. To see only the help information for the tool, the **-?** switch parameter is used. This help information will include:

* Parameter sets for installation, configuration, and uninstall

* Common command line parameters.

* General notes on how the tool works and further details on how to get more help information.

The parameters of the tool and the structure of the XML configuration file are defined in the tool Schema. This schema can be printed using the **-s "PrintSchema"** parameter; if no schema version is provided, it will print the default schema.

The tool can be run in 4 main modes; 3 of them are shown in the help message:

* **Install** - Install the driver, manifest and service on the host.

* **Configure** - Parses a given configuration file or command line parameters to generate a configuration that is stored in the registry.

* **Uninstall** - Removes the driver and service from the host.

Installation
------------

The key parameter that initiates the installation mode of Sysmon is the **-i** switch. The installation process will be as follows:

* Decompresses and copy of itself in to **/opt/sysmon**

* Creates a systemd service

* Enables a default configuration (ProcessCreation and ProcessTermination) if no configuration file is passed to the **-i** parameter.

The **-accepteula** parameter needs to be passed to accept the EULA for the tool.

Uninstall
---------

To uninstall Sysmon, a binary with the same name as the main service, if renamed, has to be run with the **-u** switch parameter.

```bash
/opt/sysmon/sysmon -u
```

When executed the command will run a series of steps to uninstall the service and remove files for the tool from **/opt/sysmon**.

The value of **force** can be passed to the **-u** parameter fo force uninstallation.

```bash
/opt/sysmon/sysmon -u force
```
