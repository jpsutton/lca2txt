#!/usr/bin/env python3

import re
import sys
import gzip
import struct
import datetime

from pprint import pprint
from dateutil import parser as dateparser
from mlargparser import MLArgParser

# This is modified from gzip._read_gzip_header
def get_gzip_headers(fp):
    ''' Extract the original filename, comment, and last modify time of a given gzip file pointer '''

    # Compatibility class for use with gzip._GzipReader._read_exact
    class fp_wrapper():
        _fp = None

    orig_filename, comment, last_mtime = None, None, None

    magic = fp.read(2)
    wrapped_fp = fp_wrapper()
    wrapped_fp._fp = fp

    if magic == b'':
        return None

    if magic != b'\037\213':
        raise BadGzipFile('Not a gzipped file (%r)' % magic)

    (method, flag, last_mtime) = struct.unpack("<BBIxx", gzip._GzipReader._read_exact(wrapped_fp, 8))

    if method != 8:
        raise BadGzipFile('Unknown compression method')

    if flag & gzip.FEXTRA:
        # Read & discard the extra field, if present
        extra_len, = struct.unpack("<H", gzip._GzipReader._read_exact(wrapped_fp, 2))
        gzip._GzipReader._read_exact(wrapped_fp, extra_len)

    if flag & gzip.FNAME:
        # Read a null-terminated string containing the filename
        while True:
            s = fp.read(1)

            if not s or s==b'\000':
                break
            else:
                if orig_filename is None:
                    orig_filename = ""
                orig_filename += s.decode("UTF-8")

    if flag & gzip.FCOMMENT:
        # Read a null-terminated string containing a comment
        while True:
            s = fp.read(1)
            if not s or s==b'\000':
                break
            else:
                if comment is None:
                    comment = ""

                comment += s.decode("UTF-8")

    if flag & gzip.FHCRC:
        gzip._GzipReader._read_exact(wrapped_fp, 2)     # Read & discard the 16-bit header CRC

    return orig_filename, comment, datetime.datetime.fromtimestamp(last_mtime)


def ticks2datetime(ticks: int):
    ''' Convert a .NET Datetime.Ticks value (very larget integer) to a Python DateTime object '''
    return datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds = ticks / 10)


def get_archive_params(archive_filename):
    ''' Read the archive paramters from the gzip comment '''

    attribs = dict()

    with open(archive_filename, "rb") as gzfile:
        orig_filename, comment, last_mtime = get_gzip_headers(gzfile)

    if comment is None:
        print("ERROR: this doesn't appear to be a LogRhythm archive file.", file=sys.stderr)
        sys.exit(1)

    m = re.match(r"^LogRhythm Archive Version=(\d+)\.(\d+)\.(\d+)", comment)

    if m is None:
        print("ERROR: this doesn't appear to be a LogRhythm archive file.", file=sys.stderr)
        sys.exit(2)

    major_version, minor_version, revision = [int(i) for i in m.groups()]
    attribs['majversion'], attribs['minversion'], attribs['revision'] = major_version, minor_version, revision
    major_minor = major_version, minor_version

    if major_minor in ((3, 6), (4, 0), (5, 0)):
        m = re.match(r"^LogRhythm Archive Version=(\d+)\.(\d+)\.(\d+) MasterLicenseID=(\d+) ArchiveGUID=(\S+) MsgSourceID=(\d+) HostID=(\d+) NormalMsgDate=(\d+) MediatorID=(\d+) CreationTicks=(\d+)", comment)
        groups = m.groups()

        if m is not None and len(groups) == 10:
            attribs['masterlicenseid'] = int(groups[3])
            attribs['archiveguid'] = groups[4]
            attribs['messagesourceid'] = int(groups[5])
            attribs['hostid'] = int(groups[6])
            attribs['normaldate'] = dateparser.parse(groups[7])
            attribs['mediatorid'] = int(groups[8])
            attribs['creationdate'] = ticks2datetime(int(groups[9]))
    elif major_minor in ((2, 2), (3, 0)):
        m = re.match(r"^LogRhythm Archive Version=(\d+)\.(\d+)\.(\d+) MsgSourceID=(\d+) HostID=(\d+) NormalMsgDate=(\d+) MediatorID=(\d+)", comment)
        groups = m.groups()

        if m is not None and len(groups) == 7:
            attribs['messagesourceid'] = int(groups[3])
            attribs['hostid'] = int(groups[4])
            attribs['normaldate'] = dateparser.parse(groups[5])
            attribs['mediatorid'] = int(groups[6])

    return attribs


def read_7bit_encoded_int(fp):
    ''' Reimplementation of Read7BitEncodedInt() from https://github.com/microsoft/referencesource/blob/master/mscorlib/system/io/binaryreader.cs '''

    count = 0
    shift = 0

    while True:
        if shift == 35:
            raise RuntimeError("Bad 7bit-encoded integer")

        b = struct.unpack("B", fp.read(1))[0]
        count |= (b & 0x7F) << shift
        shift += 7

        if (b & 0x80) == 0:
            break

    return count


def read_length_prefixed_string(fp):
    ''' Read a .NET-style length-prefixed string from a given file handle opened in binary mode '''
    length = read_7bit_encoded_int(fp)
    s = fp.read(length)
    return s.decode("UTF-8")


class Lca2txt(MLArgParser):
    """ Convert compressed LogRhythm archive files to plain text """

    argDesc = {
        'archive_filename': "Name of the archive to act on",
        'normal_msg_date': "Prefix each log entry with the NormalMsgDate",
        'server': "Hostname or IP address of a syslog server",
        'port': "Port of a syslog server",
        'protocol': "Protocol (TCP or UDP) to use when connecting to the syslog server; defaults to UDP",
    }

    def _dump(self, archive_filename: str, normal_msg_date: bool = False):
        """ Yield each line of log data to the caller """

        archive_params = get_archive_params(archive_filename)
        major_minor = (archive_params['majversion'], archive_params['minversion'])

        with gzip.open(archive_filename, "rb") as binary_reader:
            # Read and discard the header portion of the file (differs based on archive version)
            if major_minor in ((2, 2), (3, 0)):
                binary_reader.read(32)
                read_length_prefixed_string(binary_reader)
            elif major_minor in ((3, 6), (4, 0), (5, 0)):
                binary_reader.read(16)
                read_length_prefixed_string(binary_reader)
                binary_reader.read(28)
                read_length_prefixed_string(binary_reader)

            if normal_msg_date and archive_params['majversion'] < 5:
                print("WARN: --normal-msg-date/-n has no effect on archives prior to version 5", file=sys.stderr)

            while True:
                try:
                    ticks = None

                    # Read the NormalMsgDate for each line (only on version 5 archive files)
                    if archive_params['majversion'] >= 5:
                        ticks_raw = binary_reader.read(8)

                        # End of file
                        if len(ticks_raw) < 8:
                            break

                        ticks = struct.unpack("Q", ticks_raw)[0]

                    if ticks is not None and normal_msg_date:
                        sys.stdout.write(f"{ticks2datetime(ticks).isoformat()},")

                    # Read and discard line-specific metadata
                    binary_reader.read(30)
                    yield read_length_prefixed_string(binary_reader)

                except EOFError:
                    break


    def dump(self, archive_filename: str, normal_msg_date: bool = False):
        """ Dump each line of log data to standard output """

        for line in self._dump(archive_filename, normal_msg_date):
            print(line)


    def relay(self, archive_filename: str, server: str, port: int, protocol: str = "UDP", normal_msg_date: bool = False):
        """ Relay each line of log data to a syslog server """

        protocol = protocol.upper()

        if protocol not in ("UDP", "TCP"):
            print("ERROR: protocol must be 'UDP' or 'TCP'", file=sys.stderr)
            sys.exit(3)

        client = pysyslogclient.SyslogClientRFC5424(server, port, proto=protocol)

        for line in self.dump(archive_filename, normal_msg_date):
            client.log(line, program="lca2txt")

if __name__ == '__main__':
    Lca2txt()





