""" Cisco IOS XE ZTP script.

This script is intended to be downloaded by a Cisco IOS XE device to
set it up to a pre-determined configuration state.

As Cisco IOS XE uses both Python 2 and Python 3, depending on the IOS XE
version, this script has to be compatible with both versions.

Author:  Yann Gauteron
Version: development
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
DEBUG = '{{ DEBUG }}'
SYSLOG = '{{ SYSLOG }}'
DATA_URL = '{{ DATA_URL}}'

#
# DEVELOPMENT CONSTANTS
#
VERSION = '(under development)'


#
# Helper functions
#
def remove_leading_zeroes(version):
    return re.sub(r'\b0+(\d)', r'\1', version)


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
    _buffer = []

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
            out_line = '[%s] %s' % (Logger.Severity.labels[severity], line)
            print(out_line)
            Logger._buffer += out_line

            if Logger.syslog and not _skip_syslog:
                severity = min(severity, Logger.Severity.DEBUG)
                command = ('send log %d "%s"' % (severity, line))
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
    def is_chassis(self):
        if self._members is None:
            self._read_inventory()

        return bool(0 in self._members)

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
            for retry in range(Device.TRANSFER_RETRIES):
                Logger.notice('Loading "%s" (attempt: %d/%d)' %
                              (src_url, retry + 1, Device.TRANSFER_RETRIES))

                response = cli.execute('more %s' % src_url)
                match = re.match('^(%Error .*)', response)
                if match:
                    Logger.error('Error while loading file "%s"' % src_url)
                    Logger.debug(match.group(1))
                else:
                    break

            # extract file contents from output
            match = re.search('Loading %s (.*)' % src_url, response, re.DOTALL)
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
            response = cli.execute('verify /%s flash:/%s' % ('sha512' if sha512 else 'md5', filename))

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
            if member['role'] == 'Active':
                Logger.informational('Member %d has role Active. Firmware not copied.' % member['id'])
                continue

            if member['state'] == 'Provisionned':
                Logger.informational('Member %d is in state Provisionned. Firmware not copied.' % member['id'])
                continue

            Logger.notice('Copying firmware to stack member %d' % member['id'])
            cli.execute("copy flash:/%s flash-%d:/%s" % (filename, member['id'], filename))

        # Make this image bootable
        Logger.notice('Making "%s" the boot image' % filename)
        cli.configure('no boot system switch all')
        cli.configure('boot system switch all flash:/%s' % filename)

        # Copy and delete configuration to ensure the boot settings are applied
        cli.execute('copy running-config startup-config')
        cli.execute('erase nvram:')

        Logger.dev('Device.upgrade(): leaving')

    def download(self, src_url, dst_url):
        # noinspection PyPep8Naming
        ERROR_RE = re.compile('^(%Error .*)', re.MULTILINE)

        for attempt in range(Device.TRANSFER_RETRIES):
            Logger.notice('Downloading "%s" to "%s" (attempt: %d/%d)' %
                          (src_url, dst_url, attempt, Device.TRANSFER_RETRIES))

            response = cli.execute('copy %s %s' % (src_url, dst_url))
            match = ERROR_RE.search(response)
            if match:
                Logger.error('Error while downloading file "%s"' % src_url)
                Logger.debug(match.group(1))
            else:
                return True
        return False

    def _read_inventory(self):
        """ Read the device inventory and store it in the self.inventory dict. """

        xml_inventory = cli.execute('show inventory | format')
        dom_inventory = minidom.parseString(xml_inventory)

        self._inventory = []
        self._members = {}
        self._serials = []
        for entry in dom_inventory.getElementsByTagName('InventoryEntry'):
            record = {
                'chassis': entry.getElementsByTagName('ChassisName')[0].firstChild.data,
                'description': entry.getElementsByTagName('Description')[0].firstChild.data,
                'pid': entry.getElementsByTagName('PID')[0].firstChild.data,
                'vid': entry.getElementsByTagName('VID')[0].firstChild.data,
                'serial': (entry.getElementsByTagName('SN')[0].firstChild.data
                           if hasattr(entry.getElementsByTagName('SN')[0].firstChild, 'data') else ''),
            }
            self._inventory += [record]

            if record['chassis'] == '"Chassis"':
                record['id'] = 0
                self._members[0] = record
                self._serials.append(record['serial'])

            match = re.match('"Switch ([0-9])"', record['chassis'])
            if match and record['serial']:
                unit = int(match.group(1))
                record['id'] = unit
                self._members[unit] = record
                self._serials.append(record['serial'])

        response = cli.execute('show switch')
        members = [x.groupdict() for x in re.finditer(
            r'^[\s*](?P<id>[1-9]+)\s+(?P<role>(\bStandby\b)|(\bActive\b)|(\bMember\b))\s+(?P<mac>([0-9a-f]{4}\.){2}'
            r'[0-9a-f]{4})\s+(?P<priority>[0-9]+)\s+(?P<hw_version>V[0-9]+)\s+(?P<state>\S.*\S)\s+$',
            response, re.MULTILINE)]

        for record in members:
            unit = int(record['id'])
            del record['id']
            if unit in self._members:
                self._members[unit] = {**self._members[unit], **record}

    def _read_version(self):
        """ Returns a string with the IOS XE version. """

        response = cli.execute('show version')

        match = re.search('Version ([A-Za-z0-9.:()]+)', response)
        # remove leading zeroes from numbers
        self._version = remove_leading_zeroes(match.group(1)) if match else 'unknown'

        match = re.search('System image file is "(.*)"', response)
        self._bundled_packages = match and self._is_iosxe_package(match.group(1))

    def _is_iosxe_package(self, url, raise_exception_when_error=True):
        """ Returns True if the given file is an IOS XE package """
        output = cli.execute('show file information %s' % url)

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


class App(object):
    def __init__(self, data_url=None, syslog=None, debug=False):
        self._data_url = data_url
        self._syslog = syslog
        self._debug = debug

        self._data = None

        Logger.syslog(syslog)
        if self._debug:
            # TODO: Fix to DEBUG for production
            Logger.severity(Logger.Severity.DEV)

        Logger.notice('Cisco IOS-XE ZTP script started, version %s' % VERSION)
        self._device = Device()

        Logger.informational('Device IOS-XE version: %s (%s mode)' %
                             (self._device.version,
                              'bundle' if self._device.is_bundled_package else 'installed'))
        Logger.informational('Serial number(s): %s' % ', '.join(self._device.serials))
        Logger.debug('Members = %s' % str(self._device.members))

        self._download_data()

    def run(self):
        if not self._data:
            # We have no data to process...
            # Let's turn all beacon blue LEDs (if any)
            # and let the device reload in 30 minutes
            Logger.emergency('No configuration data loaded: No instructions to process further!')
            Logger.emergency('Device will reload in 30 minutes and execute ZTP process again...')

            # TODO: IMPLEMENT FOLLOWING COMMANDS
            # self._device.execute('reload in 30')
            # self._device.beacon_on()
            return

        self._stack_renumbering()
        self._software_upgrade()
        # self._process_configuration (sequences -> commands -> configuration file -> commands, ...)
        # save configuration ?
        # schedule reload ?
        # send log buffer
        # release syslog

    def _stack_renumbering(self):
        data = self._data
        if 'stack' not in data:
            Logger.debug('Configuration JSON data does not provide stacking indication. Skipped...')

        # TODO: Implement logic

    def _software_upgrade(self):
        data = self._data
        if 'software' not in data:
            Logger.debug('Configuration JSON data does not provide upgrade indication. Skipped...')
            return

        if 'url' not in data['software']:
            Logger.error('Configuration JSON data contains a "software" section, but no "url" indication. Skipped...')
            return

        self._device.upgrade(**data['software'])

    def _download_data(self):
        if not self._data_url:
            self._data = None
            return

        json_data = self._device.load(self._data_url)
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


def main():
    """
    Function called by the main entry point.

    :return: `None`
    """
    global DEBUG, SYSLOG, DATA_URL

    DEBUG = DEBUG.capitalize() == 'True'
    SYSLOG = SYSLOG or None
    DATA_URL = DATA_URL or None

    app = App(data_url=DATA_URL, syslog=SYSLOG, debug=DEBUG)
    app.run()


if __name__ == '__main__':
    main()
