""" Cisco IOS XE ZTP script.

This script is intended to be downloaded by a Cisco IOS XE device to
set it up to a pre-determined configuration state.

As Cisco IOS XE uses both Python 2 and Python 3, depending on the IOS XE
version, this script has to be compatible with both versions.

Author:  Yann Gauteron
Version: 0.0.1
"""
import base64
import cli
import json
import os
import re
import sys
import time

from xml.dom import minidom

try:
    # Python 2
    from urlparse import urljoin, urlparse
except ImportError:
    # Python 3
    from urllib.parse import urljoin, urlparse

#
# SETTINGS
#
DEBUG = '{{ DEBUG }}'  # Set to `'True'` for generating debugging logging, otherwise set to `'False'`
SYSLOG = '{{ SYSLOG }}'  # Indicate the IP address of a syslog server, or false otherwise
DATA_URL = '{{ DATA_URL }}'  # Indicate the URL address of the configuration JSON data file

#
# DEVELOPMENT CONSTANTS
#
VERSION = '(under development)'
DEVELOPMENT = True


#
# Helper functions
#
def remove_leading_zeroes(version):
    return re.sub(r'\b0+(\d)', r'\1', version)


def _make_comparable(value):
    return re.sub(r'[\W_]+', '', value).lower()


#
# Logger class
#
class Logger(object):
    """
    Logger is a logging class that provides static methods to print message to
    the console and optionally to send them to the device IOS XE logger for
    transmission to a syslog server.
    """

    class Severity:
        """
        Defines the severity level values.
        """
        EMERGENCY = 0
        ALERT = 1
        CRITICAL = 2
        ERROR = 3
        WARNING = 4
        NOTICE = 5
        INFORMATIONAL = 6
        DEBUG = 7
        DEVELOPMENT = 8  # Extra Severity for development purposes ;-)

        # Aliases
        CRIT = CRITICAL
        ERR = ERROR
        WARN = WARNING
        INFO = INFORMATIONAL
        DEV = DEVELOPMENT

        MIN = EMERGENCY
        MAX = DEVELOPMENT

        labels = {
            EMERGENCY: 'EMERGENCY',
            ALERT: 'ALERT',
            CRITICAL: 'CRITICAL',
            ERROR: 'ERROR',
            WARNING: 'WARNING',
            NOTICE: 'NOTICE',
            INFORMATIONAL: 'INFORMATIONAL',
            DEBUG: 'DEBUG',
            DEVELOPMENT: 'DEV',
        }

    _severity = Severity.INFORMATIONAL
    _syslog = None

    @staticmethod
    def syslog():
        """
        Retrieves the address of the syslog server.

        :return: the address of the syslog server
        """
        return Logger._syslog

    @staticmethod
    def syslog(value):
        """
        Sets or updates the syslog server address.

        :param value: the address of the syslog server or `None` to disable
        :return: `None`
        """
        if value == Logger._syslog:
            # Same value, let's silently return
            return

        if value is None:
            # Stop sending logs to IOS XE logger and to syslog server
            # Uninstall IOS logging
            commands = [
                'no logging host %s' % Logger._syslog,
                'no logging discriminator ztp',
            ]
        elif Logger._syslog is None:
            # Start sending logs to IOS XE logger and to syslog server
            # Install IOS logging
            commands = [
                'logging discriminator ztp msg-body includes Message from|HA_EM|INSTALL',
                'logging host %s discriminator ztp' % value,
            ]
        else:
            # Syslog server changes
            # Update IOS logging
            commands = [
                'logging host %s discriminator ztp' % value,
                'no logging host %s' % Logger._syslog,
            ]

        for command in commands:
            # noinspection PyBroadException
            try:
                cli.configure(command)
            except Exception as ex:
                Logger.error('Error while sending command "%s" to IOS' % command, _skip_syslog=True)
                Logger.debug(ex, _skip_syslog=True)
        time.sleep(2)

        Logger._syslog = value

    @staticmethod
    def severity():
        return Logger._severity

    @staticmethod
    def severity(value):
        if Logger.Severity.MIN <= value <= Logger.Severity.MAX:
            Logger._severity = value

    @staticmethod
    def log(message, severity=Severity.INFO, _skip_syslog=False):
        """
        Sends message to stdout and to IOS logging if syslog has been enabled.
        """
        if severity > Logger._severity:
            # Silently ignore message with higher severities
            return

        for line in str(message).splitlines():
            print('[%s] %s' % (Logger.Severity.labels[severity], line))

            if Logger.syslog and not _skip_syslog:
                command = ('send log %d "%s"' % (min(severity, Logger.Severity.DEBUG), line))
                # noinspection PyBroadException
                try:
                    cli.execute(command)
                except Exception as ex:
                    Logger.error('Error while sending command "%s" to IOS' % command, _skip_syslog=True)
                    Logger.debug(ex, _skip_syslog=True)
        sys.stdout.flush()

    @staticmethod
    def emergency(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.EMERGENCY, _skip_syslog=_skip_syslog)

    @staticmethod
    def alert(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.ALERT, _skip_syslog=_skip_syslog)

    @staticmethod
    def critical(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.CRITICAL, _skip_syslog=_skip_syslog)

    @staticmethod
    def error(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.ERROR, _skip_syslog=_skip_syslog)

    @staticmethod
    def warning(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.WARNING, _skip_syslog=_skip_syslog)

    @staticmethod
    def notice(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.NOTICE, _skip_syslog=_skip_syslog)

    @staticmethod
    def informational(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.INFORMATIONAL, _skip_syslog=_skip_syslog)

    @staticmethod
    def debug(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.DEBUG, _skip_syslog=_skip_syslog)

    @staticmethod
    def dev(message, _skip_syslog=False):
        Logger.log(message, severity=Logger.Severity.DEVELOPMENT, _skip_syslog=_skip_syslog)

    crit = critical
    err = error
    warn = warning
    info = informational


#
# Device class
#
# noinspection PyMethodMayBeStatic
class Device(object):
    """
    Device is a class representing the logical network entity (device) that
    provides methods to discover the device and to execute specific actions
    such as upgrading the device software, installing a default configuration,
    reordering stack members (when it applies), ...
    """

    class Keys:
        CHASSIS = 'CHASSIS'
        DESCRIPTION = 'DESCRIPTION'
        HW_VERSION = 'HW_VERSION'
        ID = 'ID'
        MAC = 'MAC'
        PID = 'PID'
        PRIORITY = 'PRIORITY'
        ROLE = 'ROLE'
        SERIAL = 'SERIAL'
        STATE = 'STATE'
        VID = 'VID'

        sortable_keys = [ID, MAC, SERIAL]

    class StackSortingOrder:
        ASCENDING = 'ASCENDING'
        DESCENDING = 'DESCENDING'

    class Beacon:
        ALL_LEDS = 'ALL'
        EVEN_LEDS = 'EVEN'
        ODD_LEDS = 'ODD'

    TRANSFER_RETRIES = 3

    def __init__(self):
        Logger.dev('Device instantiated')

        self._inventory = None
        self._members = None
        self._serials = None
        self._version = None
        self._bundled_packages = None

    @property
    def serials(self):
        if self._serials is None:
            self._read_inventory()

        # Return a copy of the serials
        return self._serials[:]

    @property
    def members(self):
        if self._members is None:
            self._read_inventory()

        return self._members

    @property
    def is_stackable(self):
        if self._members is None:
            self._read_inventory()

        return not bool(0 in self._members)

    @property
    def version(self):
        if self._version is None:
            self._read_version()

        return self._version

    @property
    def is_bundled_package(self):
        if self._bundled_packages is None:
            self._read_version()

        return self._bundled_packages

    def load(self, src_url, encoding='utf-8'):
        """ Returns file contents or empty string in case of failure """
        Logger.dev('Device.load(): entering')
        if src_url:
            Logger.dev('Device.load(): file_url="%s", encoding="%s"' % (src_url, encoding))

            response = ''
            for attempt in range(Device.TRANSFER_RETRIES):
                Logger.notice('Loading "%s" (attempt: %d/%d)' %
                              (src_url, attempt + 1, Device.TRANSFER_RETRIES))

                response = Device.execute('more %s' % src_url)
                match = re.match('^(%Error .*)', response)
                if match:
                    Logger.error('Error while loading file "%s"' % src_url)
                    Logger.debug(match.group(1))
                else:
                    break

            # extract file contents from output
            match = re.search('Loading [^\n]+\n(.*)', response, re.DOTALL)
            if match:
                result = self._parse_hex(match.group(1), encoding)
                Logger.dev('Device.load(): leaving returning %d bytes' % len(result))
                return result
            else:
                Logger.dev('Device.load(): leaving returning None (file loading failed)')
                return
        else:
            Logger.dev('Device.load(): leaving returning None (file_url evaluates to False)')
            return

    # noinspection PyUnusedLocal
    def upgrade(self, url, version=None, sha512=None, md5=None, **kwargs):
        """
        Upgrade software of the device.

        :param url: the full URL of the software to be used if upgrade is required
        :param version: the target version of the software (if not specified, the method tries to make an educated
        guess based on the filename specified in `url`)
        :param sha512: the SHA512 checksum value used to verify the downloaded file integrity
        :param md5: the MD5 checksum value used to verify the downloaded file integrity
        :param kwargs: catch-all parameter (for ensuring upward-compatibility), these parameters are silently ignored
        :return: `None`
        """
        Logger.dev('Device.upgrade(): entering')
        Logger.dev('Device.upgrade(): url="%s"' % url)
        if version:
            Logger.dev('Device.upgrade(): version="%s"' % version)
        if sha512:
            Logger.dev('Device.upgrade(): sha512="%s"' % sha512)
        if md5:
            Logger.dev('Device.upgrade(): md5="%s"' % md5)

        url_parsed = urlparse(url)
        filename = os.path.basename(url_parsed.path)

        if version is None:
            match = re.match(r'.*\.([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9]*)\..*', filename)
            version = remove_leading_zeroes(match.group(1)) if match else ''
        else:
            version = remove_leading_zeroes(version)

        if self.version == version and version != '':
            Logger.info('Current version %s matches target version %s. Upgrade skipped...' % (self.version, version))
            Logger.dev('Device.upgrade(): leaving')
            return

        Logger.notice('Upgrade required (current version: %s; target version: %s)' %
                      (self.version, version))

        # Copy file
        if not self.download(url, 'flash:/%s' % filename):
            Logger.alert('Error while trying to download "%s". Upgrade skipped...' % url)
            Logger.dev('Device.upgrade(): leaving')
            return

        # Checksum verification
        if sha512 or md5:
            Logger.notice('Verifying %s checksum.' % ('SHA512' if sha512 else 'MD5'))
            response = Device.execute('verify /%s flash:/%s' % ('sha512' if sha512 else 'md5', filename))

            checksum = re.search('([a-fA-F0-9]{%d})' % (128 if sha512 else 32), response).group(1).strip().lower()
            if not (sha512 and checksum == sha512.strip().lower()) and not (md5 and checksum == md5.strip().lower()):
                Logger.alert('Error while verifying SHA512/MD5 checksum. Upgrade aborted...')
                Logger.debug('Computed checksum: %s\nExpected checksum: %s' %
                             (checksum, sha512 if sha512 else md5))
                Logger.dev('Device.upgrade(): leaving')
                return
        else:
            Logger.informational('No checksum provided. Continuing...')

        # Copy image to other stack members
        members = self.members
        for i in members.keys():
            member = members[i]
            if member[Device.Keys.ROLE] == 'Active':
                Logger.informational('Member %s has role Active. Firmware not copied.' % member[Device.Keys.ID])
                continue

            if member[Device.Keys.STATE] == 'Provisionned':
                Logger.informational('Member %s is in state Provisionned. Firmware not copied.'
                                     % member[Device.Keys.ID])
                continue

            Logger.notice('Copying firmware to stack member %s' % member[Device.Keys.ID])
            Device.execute("copy flash:/%s flash-%s:/%s" % (filename, member[Device.Keys.ID], filename))

        # Make this image bootable
        Logger.notice('Making "%s" the boot image' % filename)
        Device.configure('no boot system switch all')
        Device.configure('boot system switch all flash:/%s' % filename)

        # Copy and delete configuration to ensure the boot settings are applied
        Device.execute('copy running-config startup-config')
        Device.execute('erase nvram:')

        Logger.dev('Device.upgrade(): leaving')

    # noinspection PyUnusedLocal
    def configure_stack_members(self, keys=Keys.MAC, order=StackSortingOrder.ASCENDING, **kwargs):
        """
        Configure the stack members.

        :param keys: the keys used to determine the ordering of the stack members, can be 'MAC' (the default),
        'SERIAL', or 'ID'
        :param order: the ordering of the stack members, can be 'ASCENDING', 'DESCENDING' or a comma-separated list of
        key values
        :return: `None`
        """
        Logger.dev('Device.configure_stack_members(): entering')
        Logger.dev('Device.configure_stack_members(): keys="%s"' % keys)
        Logger.dev('Device.configure_stack_members(): order="%s"' % order)

        if not self.is_stackable:
            Logger.error('Device seems not to be a stack. Stack configuration aborted...')
            Logger.debug('is_stackable = %s' % str(self.is_stackable))
            Logger.dev('Device.configure_stack_members(): leaving')
            return

        Logger.notice('Renumbering stack members')

        if keys not in Device.Keys.sortable_keys:
            Logger.error('Invalid value for "keys" given in "stack" configuration (received value: "%s").'
                         ' Aborting stack renumbering...' % keys)
            Logger.dev('Device.configure_stack_members(): leaving')
            return

        members = self.members

        # List of indices of members in current order
        current_order = [index for index in members.keys()]

        # Determine the target order
        target_order = []
        if order in [Device.StackSortingOrder.ASCENDING, Device.StackSortingOrder.DESCENDING]:
            # Use device properties to determine the target order
            if keys == Device.Keys.ID:
                target_order = sorted(members.keys())
            else:
                target_order = sorted(members, key=lambda index: members[index][keys])

            if order == Device.StackSortingOrder.DESCENDING:
                target_order.reverse()
        else:
            all_devices = sorted(members.keys())
            order_list = order.split(',')

            if keys == Device.Keys.ID:
                for item in order_list:
                    try:
                        idx = int(item)
                        if idx in all_devices:
                            target_order.append(idx)
                        else:
                            Logger.error('ID provided in stack.order list does not represent an existing member'
                                         ' (invalid ID: %d). Ignoring value.' % idx)
                    except ValueError as ex:
                        Logger.error('Invalid ID provided in stack.order list (invalid ID: "%s"). Ignoring value'
                                     % item)
            else:
                for item in order_list:
                    index = None
                    for idx, member in members.items():
                        if _make_comparable(member[keys]) == _make_comparable(item):
                            index = idx
                            break
                    if index:
                        target_order.append(index)
                    else:
                        Logger.error('%s provided in stack.order list does not represent an existing equipment'
                                     ' (invalid %s: %s). Ignoring value.' % (keys, keys, item))

            # Remove possible duplicates
            target_order = list(dict.fromkeys(target_order))

            # Add possible devices that are not included in stack.order
            missing_devices = sorted(list(set(all_devices) - set(target_order)))
            target_order += missing_devices

        for i, idx in enumerate(target_order):
            Logger.informational('Processing member %d (MAC: %s; Serial: %s). Set ID=%d, priority=%d' %
                                 (idx, members[idx][Device.Keys.MAC], members[idx][Device.Keys.SERIAL],
                                  i+1, max(15-i, 1)))

            Device.execute('switch %d renumber %d' % (idx, i+1))
            Device.execute('switch %d priority %d' % (idx, max(15-i, 1)))
            Device.execute('delete flash-%d:nvram_config' % idx)

        Logger.dev('Device.configure_stack_members(): leaving')

    def download(self, src_url, dst_url):
        # noinspection PyPep8Naming
        ERROR_RE = re.compile('^(%Error .*)', re.MULTILINE)

        for attempt in range(Device.TRANSFER_RETRIES):
            Logger.notice('Downloading "%s" to "%s" (attempt: %d/%d)' %
                          (src_url, dst_url, attempt + 1, Device.TRANSFER_RETRIES))

            response = Device.execute('copy %s %s' % (src_url, dst_url))
            match = ERROR_RE.search(response)
            if match:
                Logger.error('Error while downloading file "%s"' % src_url)
                Logger.debug(match.group(1))
            else:
                return True
        return False

    def beacon_on(self, nodes):
        """ Turns on blue beacon of given switch number list, if supported. """
        self._beacon(nodes, True)

    def beacon_off(self, nodes):
        """ Turns off blue beacon of given switch number list, if supported. """
        self._beacon(nodes, False)

    def _beacon(self, nodes, state):
        if nodes == Device.Beacon.ALL_LEDS:
            nodes = list(self.members.keys())
        elif nodes == Device.Beacon.EVEN_LEDS:
            nodes = list(filter(lambda key: key % 2 == 0, self.members.keys()))
        elif nodes == Device.Beacon.ODD_LEDS:
            nodes = list(filter(lambda key: key % 2 == 1, self.members.keys()))

        if not isinstance(nodes, list):
            Logger.error('Invalid value given to beacon_on() or beacon_off()')
            Logger.debug('nodes = %s' % str(nodes))
            return

        for index in nodes:
            on_off = 'on' if state else 'off'

            # Up to and including 16.8.x
            Device.cli('configure terminal ; hw-module beacon %s switch %d' % (on_off, index))

            # From 16.9.x onwards
            Device.execute('hw-module beacon slot %d %s' % (index, on_off))

            Logger.informational('Switch %d beacon LED turned %s' % (index, on_off))

    def _read_inventory(self):
        """ Read the device inventory and store it in the self.inventory dict. """

        xml_inventory = Device.execute('show inventory | format')
        dom_inventory = minidom.parseString(xml_inventory)

        self._inventory = []
        self._members = {}
        self._serials = []
        for entry in dom_inventory.getElementsByTagName('InventoryEntry'):
            record = {
                Device.Keys.CHASSIS: entry.getElementsByTagName('ChassisName')[0].firstChild.data,
                Device.Keys.DESCRIPTION: entry.getElementsByTagName('Description')[0].firstChild.data,
                Device.Keys.PID: entry.getElementsByTagName('PID')[0].firstChild.data,
                Device.Keys.VID: entry.getElementsByTagName('VID')[0].firstChild.data,
                Device.Keys.SERIAL: (entry.getElementsByTagName('SN')[0].firstChild.data
                                     if hasattr(entry.getElementsByTagName('SN')[0].firstChild, 'data') else ''),
            }
            self._inventory += [record]

            if record[Device.Keys.CHASSIS] == '"Chassis"':
                record[Device.Keys.ID] = '0'  # Enforce ID to be a string
                self._members[0] = record
                self._serials.append(record[Device.Keys.SERIAL])

            match = re.match(r'"Switch ([0-9])"', record[Device.Keys.CHASSIS])
            if match and record[Device.Keys.SERIAL]:
                unit = int(match.group(1))
                record[Device.Keys.ID] = str(unit)  # Enforce ID to be a string
                self._members[unit] = record
                self._serials.append(record[Device.Keys.SERIAL])

        response = Device.execute('show switch')
        members = [x.groupdict() for x in re.finditer(
            r'^[\s*](?P<ID>[1-9]+)\s+(?P<ROLE>(\bStandby\b)|(\bActive\b)|(\bMember\b))\s+(?P<MAC>([0-9a-f]{4}\.){2}'
            r'[0-9a-f]{4})\s+(?P<PRIORITY>[0-9]+)\s+(?P<HW_VERSION>V[0-9]+)\s+(?P<STATE>\S.*\S)\s+$',
            response, re.MULTILINE)]

        for record in members:
            unit = int(record[Device.Keys.ID])
            del record[Device.Keys.ID]
            if unit in self._members:
                self._members[unit] = {**self._members[unit], **record}

    def _read_version(self):
        """ Returns a string with the IOS XE version. """

        response = Device.execute('show version')

        match = re.search('Version ([A-Za-z0-9.:()]+)', response)
        # remove leading zeroes from numbers
        self._version = remove_leading_zeroes(match.group(1)) if match else 'unknown'

        match = re.search('System image file is "(.*)"', response)
        self._bundled_packages = match and self._is_iosxe_package(match.group(1))

    def _is_iosxe_package(self, url, raise_exception_when_error=True):
        """ Returns True if the given file is an IOS XE package """
        output = Device.execute('show file information %s' % url)

        # log error message if any and terminate script in case of failure
        match = re.match('^(%Error .*)', output)
        if match:
            Logger.error(match.group(1))
            if raise_exception_when_error:
                raise Exception(match.group(1))

        return bool(re.search('IFS|NOVA|IOSXE_PACKAGE', output))

    def _parse_hex(self, data, encoding='utf-8'):
        """ Converts a hex/text format of the IOS more command to string """
        match = re.findall(r'\S{8}: +(\S{8} +\S{8} +\S{8} +\S{8})', data)
        parts = [base64.b16decode(re.sub('[ X]', '', line)).decode(encoding) for line in match]
        return ''.join(parts) if match else data

    @staticmethod
    def cli(commands, display=False):
        result = ''

        if isinstance(commands, str):
            commands = [commands]
        if not isinstance(commands, list):
            return result

        for command in commands:
            Logger.dev('COMMAND: [CLI] %s' % command)
            try:
                response = cli.cli(command)
                result += response
                if display:
                    print(response)
                if response.strip() != '':
                    Logger.dev('%s\n%s\n%s\n' % (80 * 'v', response, 80 * '^'))
            except Exception as ex:
                Logger.dev('ERROR:\n%s\n%s\n%s\n' % (80 * 'v', ex, 80 * '^'))
                Logger.error('Error while sending command "%s" to IOS' % command)
                Logger.debug(ex)

        return result

    @staticmethod
    def clip(commands):
        return Device.cli(commands, True)

    @staticmethod
    def configure(commands):
        if isinstance(commands, str):
            commands = [commands]
        if not isinstance(commands, list):
            return

        for command in commands:
            Logger.dev('COMMAND: [CONFIG] %s' % command)
            try:
                cli.configure(command)
            except Exception as ex:
                Logger.dev('ERROR:\n%s\n%s\n%s\n' % (80 * 'v', ex, 80 * '^'))
                Logger.error('Error while sending command "%s" to IOS' % command)
                Logger.debug(ex)

    @staticmethod
    def configurep(commands):
        return Device.configure(commands)

    @staticmethod
    def execute(commands, display=False):
        result = ''

        if isinstance(commands, str):
            commands = [commands]
        if not isinstance(commands, list):
            return result

        for command in commands:
            Logger.dev('COMMAND: [EXEC] %s' % command)
            try:
                response = cli.execute(command)
                result += response
                if display:
                    print(response)
                if response.strip() != '':
                    Logger.dev('%s\n%s\n%s\n' % (80 * 'v', response, 80 * '^'))
            except Exception as ex:
                Logger.dev('ERROR:\n%s\n%s\n%s\n' % (80 * 'v', ex, 80 * '^'))
                Logger.error('Error while sending command "%s" to IOS' % command)
                Logger.debug(ex)

        return result

    @staticmethod
    def executep(commands):
        return Device.execute(commands, True)


class App(object):
    def __init__(self, data_url=None, syslog=None, debug=False, _development=False):
        self._data_url = data_url
        self._syslog = syslog
        self._debug = debug
        self._development = _development

        self._data = None
        self._save = False
        self._reload = None
        self._exit_value = 0

        Logger.syslog(syslog)
        if self._debug:
            Logger.severity(Logger.Severity.DEBUG if not self._development else Logger.Severity.DEVELOPMENT)

        Logger.notice('Cisco IOS-XE ZTP script started, version %s' % VERSION)
        self._device = Device()

        Logger.informational('Device IOS-XE version: %s (%s mode)' %
                             (self._device.version,
                              'bundle' if self._device.is_bundled_package else 'installed'))
        Logger.informational('Serial number(s): %s' % ', '.join(self._device.serials))
        Logger.debug('Members = %s' % str(self._device.members))

        self._download_data()

    def run(self):
        if self._data:
            self._stack_members_configuration()
            self._software_upgrade()
            self._configuration()

            self._save_configuration()
            self._process_reload()
        else:
            # We have no data to process...
            Logger.emergency('No configuration data loaded: No instructions to process further!')
            self._device.beacon_on(Device.Beacon.ALL_LEDS)
            # We set a reload delay of 30 minutes to prevent the device to get stuck in bootloader
            # if excessive reloads occurs in a short time
            self._reload = 30

        self._shutdown()

    def _get_querystring(self):
        members = self._device.members

        indices = list(members.keys())
        macs = [members[member][Device.Keys.MAC] for member in members.keys()]
        serials = [members[member][Device.Keys.SERIAL] for member in members.keys()]
        models = [members[member][Device.Keys.PID] for member in members.keys()]

        querystr_main = ''
        querystr_macs = querystr_serials = querystr_models = ''
        for i, index in enumerate(indices):
            print('index = %d' % index)
            if i == 0:
                querystr_main = ('MAC=%s&SERIAL=%s&MODEL=%s&NB_MEMBERS=%d'
                                 % (macs[i], serials[i], models[i], len(indices)))
            else:
                querystr_macs += '&'
                querystr_serials += '&'
                querystr_models += '&'
            querystr_macs += 'MAC__%d=%s' % (index, macs[i])
            querystr_serials += 'SERIAL__%d=%s' % (index, serials[i])
            querystr_models += 'MODEL__%d=%s' % (index, models[i])
        return '%s&%s&%s&%s' % (querystr_main, querystr_macs, querystr_serials, querystr_models)

    def _download_data(self):
        if not self._data_url:
            self._data = None
            return

        url = '%s?%s' % (self._data_url, self._get_querystring())
        json_data = self._device.load(url)
        if not json_data:
            self._data = None
            return

        try:
            data = json.loads(json_data)
        except json.JSONDecodeError as ex:
            Logger.error('Loaded file is not a valid JSON file')
            Logger.debug(ex)
            return

        self._data = data
        Logger.dev('Data file downloaded:')
        Logger.dev(data)
        return data

    def _stack_members_configuration(self):
        data = self._data
        if 'stack' not in data:
            Logger.debug('Configuration JSON data does not provide stacking indication. Skipped...')
            return

        self._device.configure_stack_members(**data['stack'])

    def _software_upgrade(self):
        data = self._data
        if 'software' not in data:
            Logger.debug('Configuration JSON data does not provide upgrade indication. Skipped...')
            return

        if 'url' not in data['software']:
            Logger.error('Configuration JSON data contains a "software" section, but no "url" indication. Skipped...')
            return

        self._device.upgrade(**data['software'])

    def _configuration(self):
        data = self._data
        if 'configuration' not in data:
            Logger.debug('Configuration JSON data does not provide device'
                         ' configuration tasks. Skipped...')
            return

        configuration = data['configuration']
        tasks = dict(sorted(configuration.items(), key=lambda k: int(k[0])))
        for key, task in tasks.items():
            Logger.info('Processing configuration task #%d' % int(key))

            if 'type' not in task:
                Logger.error('Type is not provided. Skipped...')
                continue

            task_type = task['type']
            if (task_type in ['configuration', 'exec']
                    and 'commands' not in task):
                Logger.error('No commands specified for %s task. Skipped...' %
                             task_type)
                continue
            if (task_type in ['running-config', 'startup-config']
                    and 'url' not in task):
                Logger.error('No url specified for %s task. Skipped...' %
                             task_type)
                continue

            if task_type == 'configuration':
                Device.configure(task['commands'])
            elif task_type == 'exec':
                Device.execute(task['commands'])
            elif task_type == 'running-config':
                self._device.download(task['url'], 'running-config')
            elif task_type == 'startup-config':
                self._device.download(task['url'], 'startup-config')
            else:
                Logger.error('No recognized type %s. Skipped...' % task_type)

    def _save_configuration(self):
        data = self._data
        if 'save' not in data:
            Logger.debug('Configuration JSON data does not provide saving indication. Skipped...')
            return

        self._save = (data['save'].capitalize() == 'True')

    def _process_reload(self):
        data = self._data
        if 'reload' not in data:
            Logger.debug('Configuration JSON data does not provide reload indication. Skipped...')
            return

        if 'delay' not in data['reload']:
            self._reload = 0
        else:
            try:
                self._reload = int(data['reload']['delay'])
            except ValueError:
                self._reload = 0

        if self._reload < 1:
            # We set a 1 minute delay, so the script can properly exit
            self._reload = 1

    def _shutdown(self):
        if self._save is True:
            Logger.notice('Saving configuration')
            self._device.execute('copy running-config startup-config')

        if self._reload is not None:
            # noinspection PyStringFormat
            Logger.informational('Reloading the device in %d minute(s)' % self._reload)
            # noinspection PyStringFormat
            cli.execute('reload in %d' % self._reload)

        Logger.syslog(None)

        self._device = None
        sys.exit(int(self._exit_value))


def main():
    """
    Function called by the main entry point.

    :return: `None`
    """
    global DEBUG, SYSLOG, DATA_URL, DEVELOPMENT
    DEBUG = DEBUG.capitalize() == 'True'
    SYSLOG = SYSLOG or None
    DATA_URL = DATA_URL or None
    DEVELOPMENT = globals()['DEVELOPMENT'] if 'DEVELOPMENT' in globals() else False

    app = App(data_url=DATA_URL, syslog=SYSLOG, debug=DEBUG, _development=DEVELOPMENT)
    app.run()


if __name__ == '__main__':
    main()
