# Introduction
The `script.py` is a script intended to be downloaded by a Cisco IOS-XE device during its ZTP (Zero Touch Provisioning) process.

This script can execute the following tasks:
* Reorder and configure the members of a Catalyst switch stack (on Cisco Catalyst 9300 devices for instance)
* Download and upgrade the IOS-XE software image to a target version
* Execute isolated commands, download and copy configuration file to the startup-config or the running-config
* Save the configuration
* Reload the device

All these actions can be executed upon configuration that is downloaded by the script.

## Embedded configuration
The script has a minimum number of settings that are embedded within the script. These are:
* `DEBUG` that should be a string with either `"True"` or `"False"`. When `DEBUG` is set to `"True"` additional debugging information are logged.
* `SYSLOG` that optionally indicate the IP address of a SYSLOG server where all logs are sent. It is disabled with an empty string.
* `DATA_URL` that must indicate the URL where the device will read its configuration JSON data. The content of that file is described below.

## Configuration JSON data
Configuration JSON data are sent upon request of the device at `DATA_URL`. The script determines its behavior based on the content of that file.

This file must be a well-formed regular JSON file that contains different data to cause the script to execute different actions.

### Stack members configuration and renumbering
The script can renumber and configure the stack so it has a predefined state.

In order to have the script executing this task, the JSON data must contain an object named `stack` (case is important):
* `stack`: object indicating the device should reconfigure its stack
  * `keys`: optional parameter that indicates the keys used to order the stack members. Its value can be `SERIAL` (for serial numbers used as keys), `MAC` (for MAC addresses used as keys), `ID` (for current switch ID used as keys)
  * `order`: optional parameter that indicates the expected final order of the stack members. Its value can be `ASCENDING` (for ordering the device based on the key value in ascending order - smaller key will become master), `DESCENDING` (for ordering the device based on the key value in descending order - higher key will become master), or a string containg the list of key values in the expected order with each value separated with a comma `,` (first value will become master, non-existant values will become ignored, stack members without any specified values will be sorted then according their current ID)

If `keys` is absent, the default key is `MAC`; if `order` is absent, the default ordering is `ASCENDING`.

#### Example
```
{
    "stack": {
        "keys": "MAC",
        "order": "ASCENDING"
    }
}
```

### Software upgrade
The script can upgrade the software of the device.

In order to have the script executing this task, the JSON data must contain an object named `software` (case is important):
* `software`: object indicating the device should verify and upgrade its software if necessary
  * `url`: mandatory parameter that indicates the complete URL to download the target software;
  * `version`: optional parameter that indicates the version of the target software to determine if the software should be upgraded (when the current version and the target version differs), when absent, the script tries to make an educated guess based on the filename indicated in the `url`;
  * `sha512`: optional parameter that indicates the SHA512 checksum value used to verify the downloaded file has not been corrupted during transfer,
  * `md5`: optional parameter that indicated the MD5 checksum value used to verify the downloaded file has not been corrupted during transfer.
    
Note that both `sha512` and `md5` are optional. When both are missing, no file integrity verification is performed. If one is indicated (if the device supports this verification algorithm), it is used to verify the transfer integrity and, if this fails, the software is not configured as boot image. When both values are indicated, SHA512 is used, short-circuiting MD5 verification.

#### Example
```
{
    "software": {
        "url": "http://192.168.199.254/firmwares/cat9k_iosxe.17.03.02a.SPA.bin",
        "version": "17.03.02a",
        "sha512": "6cec116c6f283460dd8e900073c751aa0e0361237bdd7f1613c790dd75ebd97c13f12476cae77a871bbac312677d9e3cc145d00df1634449d5d2e0e70690d82e",
        "md5": "3cc37b28a564064485e767ebc3a1f2f8"
}
```

### Configuration
The script can apply configuration to the device. This can be set line by line,
by downloading and applying a configuration to the running-config, by
downloading and applying a configuration to the startup-config, by executing a
command, or with a combination of the above.

In order to have the script executing configuration task, the JSON data must
contain an object named `configuration` (case is important):
* `configuration`: object indicating the device should perform configuration
  tasks, the object contains as much entries as the number of distinct
  successive configuration tasks needed.
  * task number: Each entry contains a number coded in a string (JSON does not
    allow keys to be something else than a string) that acts as a sequence 
    number. Tasks are executed in the ascending order of the sequence numbers
    (sorted in regards of the numerical comparison). 
    * `type`: Different types of entries are possible: `configuration` that
      specifies command(s) to be sent to Cisco IOS-XE CLI configuration mode, 
      `exec` that specifies commands to be sent to Cisco IOS-XE CLI exec mode, 
      `running-config` that specifies an URL to be downloaded into the 
      `running-config` using the CLI `copy` command, and `startup-config` that 
      specifies an URL to be downloaded into  the `startup-config` using the CLI
      `copy` command.
    * `commands`: (for `configuration` and `exec` types only) list with
      individual commands to be sent to the device in either the configuration
      or the exec mode.
    * `url`: (for `running-config` and `startup-config` types only) string with
      the URL to retrieve the configuration to be copied to either 
      `running-config` or `startup-config`.

#### Example
```
{
  "configuration": {
    "1": {
      "type": "configuration",
      "commands": [
        "interface range GigabitEthernet1/0/1-48",
        "shutdown"
      ]
    },
    "2": {
      "type": "running-config",
      "url": "http://10.0.0.1/CONFIG.cfg"
    },
    "3": {
      "type": "startup-config",
      "url": "http://10.0.0.1/CONFIG.cfg"
    },
    "4": {
      "type": "exec",
      "commands": [
        "clear ip ospf 1 process"
      ]
    }
  }
}
```

### Configuration saving
At the end of the script execution, current configuration can be saved for persisting over reboot.

Note that if you already applied some changes into the device `startup-config`, saving configuration will overwrite any previous changes.

To indicate the script to save the current configuration, the JSON data must contain a string named `save` that contains the value `"True"`

#### Example
```
{
    "save": "True"
}
```

### Device reload
At the end of the script execution, the device can be reloaded. The configuation JSON data can indicate if the device has to be reloaded, and the delay for such reboot.

In order to have the device reloaded, the JSON data must contain an object named `reload` (case is important):
* `reload`: object indicating the device should reload at the end of the script execution
  * `delay`: optional parameter indicating the delay, in minutes, between the end of the script and the reload is initiated (defaults to 1 minute - see the note below).

Note that the script imposes a minimum delay of 1 minute, so it can properly finishes its execution.

#### Example
```
{
    "reload": {
        "delay": 1
    }
}
```
