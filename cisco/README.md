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
  * `order`: optional parameter that indicates the expected final order of the stack members. Its value can be `ASCENDING` (for ordering the device based on the key value in ascending order - smaller key will become master), ´DESCENDING´ (for ordering the device based on the key value in descending order - higher key will become master), or a string containg the list of key values in the expected order with each value separated with a comma `,` (first value will become master, non-existant values will become ignored, stack members without any specified values will be sorted then according their current ID)

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