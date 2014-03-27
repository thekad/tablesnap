#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

from __future__ import absolute_import

import argparse
import boto
import grp
import os
import pwd
import pyinotify
import Queue
import re
import signal
import socket
import StringIO
import sys
import traceback
import threading
import time
assert time

from . import base


# Setup logging and debugging levels
LOGGER, DEBUG = base.set_logger('tablesnap')

# Default retries
DEFAULT_RETRIES = 1

# Max file size to upload without doing multipart in MB (5Gb as per AWS)
DEFAULT_MAX_FILE_SIZE = 5120

# Default chunk size for multipart uploads in MB
DEFAULT_CHUNK_SIZE = 256

# Choices for listen events
LISTEN_EVENTS = [
    'IN_MOVED_TO',
    'IN_CLOSE_WRITE',
    'IN_CREATE',
    'IN_MODIFY',
]

# Default inotify events to listen on
DEFAULT_LISTEN_EVENTS = ['IN_MOVED_TO']

# Default filtering
DEFAULT_INCLUDE = lambda path: path.find('-tmp') == -1


def get_fs_meta(filename):
    """
    Gets the filesystem metadata of a given file
    """

    meta = None
    if os.path.isfile(filename):
        try:
            stat = os.stat(filename)
        except OSError:
            # File removed?
            return None

        meta = {'uid': stat.st_uid,
                'gid': stat.st_gid,
                'mode': stat.st_mode}
        try:
            u = pwd.getpwuid(stat.st_uid)
            meta['user'] = u.pw_name
        except:
            pass

        try:
            g = grp.getgrgid(stat.st_gid)
            meta['group'] = g.gr_name
        except:
            pass

    return meta


def get_mask(listen_events=DEFAULT_LISTEN_EVENTS):
    """
    Gets the mask to be acted upon based on inotify events
    """

    if set(listen_events).difference(LISTEN_EVENTS):
        raise ValueError(
            'You supplied an incorrect value for listen_events, correct values: %s' % (
                ','.join(LISTEN_EVENTS),
            )
        )
    mask = 0
    for event in listen_events:
        attr = getattr(pyinotify, event.upper())
        mask = mask | attr

    return mask


def save_snapshot(filenames):
    """
    Saves a directory listing to the root of the target with a timestamp
    """

    pass


def backup_file(handler, filename, include=None, log=LOGGER, save_snapshot=False):
    """
    Backups a single file given an upload handler
    """

    if os.path.isdir(filename):
        return

    if include is None or (
        include is not None
        and include(filename)
    ):
        log.info('Skipping %s due to exclusion rule' % (filename,))
        return

    handler.add_file(filename, save_snapshot)
    return


def backup_files(handler, paths, recurse, include=None, log=LOGGER):
    """
    Backups a list of directories via an upload handler. These directories
    can be recursively uploaded and filtered
    """

    snapshot = base.get_dir_snapshot(paths, recurse, include)
    for filename in snapshot:
        log.info('Backing up %s' % (filename,))
        backup_file(handler, filename, include)
    return save_snapshot(snapshot)


def get_free_memory_in_kb():
    """
    Returns the available free memory in Unix systems by examining
    /proc/meminfo. Perhaps if (ever) windows is supported we can change this
    """

    f = open(os.path.join('proc', 'meminfo'), 'r')
    memlines = f.readlines()
    f.close()
    lines = []
    for line in memlines:
        ml = line.rstrip(' kB\n').split(':')
        lines.append((ml[0], int(ml[1].strip())))
    d = dict(lines)
    return d['Cached'] + d['MemFree'] + d['Buffers']


class UploadHandler(pyinotify.ProcessEvent):
    def my_init(
        self, key, secret, bucket_name,
        threads=base.DEFAULT_THREADS,
        prefix='', name=socket.getfqdn(),
        max_size=DEFAULT_MAX_FILE_SIZE,
        chunk_size=DEFAULT_CHUNK_SIZE,
        include=DEFAULT_INCLUDE, log=LOGGER,
        md5_on_start=False, debug=DEBUG,
        retries=DEFAULT_RETRIES,
        without_index=False,
        recurse=False,
    ):
        self.key = key
        self.secret = secret
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.name = name
        self.retries = retries
        self.log = log
        self.include = include
        self.md5_on_start = md5_on_start
        self.debug = debug
        self.without_index = without_index
        self.recurse = recurse

        self.max_size = max_size * 2**20
        self.chunk_size = chunk_size * 2**20

        self.fileq = Queue.Queue()
        for i in range(int(threads)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()

    def _bucket(self):
        """
        Returns a new bucket connected to s3
        """

        return base.get_bucket(
            base.s3_connect(
                self.key, self.secret, self.debug
            ), self.bucket_name
        )

    def add_file(self, filename, save_snapshot=False):
        """
        Adds a file to be uploaded to the internal Queue
        """

        if self.include is None or (
            self.include is not None
            and self.include(filename)
        ):
            self.fileq.put((filename, save_snapshot))
        else:
            self.log.info('Skipping %s due to exclusion rule' % filename)

    def process_default(self, event):
        """
        Default file processing for all events
        """

        self.add_file(event.pathname, save_snapshot=True)

    def key_exists(self, bucket, keyname, filename, stat):
        """
        Check if this keyname (ie, file) has already been uploaded to
        the S3 bucket. This will verify that not only does the keyname
        exist, but that the MD5 sum is the same -- this protects against
        partial or corrupt uploads. IF you enable md5 at start
        """

        key = None
        for r in range(self.retries):
            try:
                key = bucket.get_key(keyname)
                if key is None:
                    self.log.debug('Key %s does not exist' % (keyname,))
                    return False
                else:
                    self.log.debug('Found key %s' % (keyname,))
                    break
            except:
                # Might have lost connection, reconnect
                bucket = self._bucket()
                continue

        else:
            self.log.critical(
                'Failed to lookup keyname %s after %d retries' % (
                    keyname, self.retries,
                )
            )
            self.log.critical(traceback.format_exc())
            raise

        if key.size != stat['size']:
            self.log.warning(
                'ATTENTION: your source (%s) and target (%s) '
                'sizes differ, you should take a look. As immutable files '
                'never change, one must assume the local file got corrupted '
                'and the right version is the one in S3. Will skip this file '
                'to avoid future complications' % (filename, keyname, )
            )
            return True
        else:
            if not self.md5_on_start:
                # Don't bother computing MD5 at startup
                return True
            else:
                # Compute MD5 sum of file
                try:
                    fp = open(filename, 'rb')
                except IOError as (errno, strerror):
                    if errno == 2:
                        # The file was removed, return True to skip this file.
                        return True

                    self.log.critical(
                        'Failed to open file: %s (%s)\n%s' % (
                            filename, strerror, traceback.format_exc(),
                        )
                    )
                    raise

                md5 = key.compute_md5(fp)
                fp.close()
                self.log.debug('Computed md5: %s' % (md5,))

                md5sum = key.get_metadata('md5sum')

                if md5sum:
                    self.log.debug('MD5 metadata comparison: %s == %s? : %s' %
                                  (md5[0], md5sum, (md5[0] == md5sum)))
                    result = (md5[0] == md5sum)
                else:
                    self.log.debug(
                        'ETag comparison: %s == %s? : %s' % (
                            md5[0], key.etag.strip('"'),
                            (md5[0] == key.etag.strip('"')),
                        )
                    )
                    result = (md5[0] == key.etag.strip('"'))
                    if result:
                        self.log.debug('Setting missing md5sum metadata for %s' %
                                      (keyname,))
                        key.set_metadata('md5sum', md5[0])

                if result:
                    self.log.info(
                        'Keyname %s already exists, skipping upload' % (
                            keyname
                        )
                    )
                else:
                    self.log.warning(
                        'ATTENTION: your source (%s) and target (%s) '
                        'MD5 hashes differ, you should take a look. As immutable '
                        'files never change, one must assume the local file got '
                        'corrupted and the right version is the one in S3. Will '
                        'skip this file to avoid future complications' % (
                            filename, keyname,
                        )
                    )

                return result

    def split_file(self, filename):
        """
        A generator that yields chunks of a given file based on how parameters
        or how much available memory there is in the system
        """

        free = get_free_memory_in_kb() * 1024
        self.log.debug(
            'Free memory check: %d < %d ? : %s' % (
                free, self.chunk_size, (free < self.chunk_size),
            )
        )
        if free < self.chunk_size:
            self.log.warn('Your system is low on memory, '
                          'reading in smaller chunks')
            chunk_size = free / 20
        else:
            chunk_size = self.chunk_size
        self.log.debug('Reading %s in %d byte sized chunks' %
                       (filename, chunk_size))
        f = open(filename, 'rb')
        while True:
            chunk = f.read(chunk_size)
            if chunk:
                yield StringIO.StringIO(chunk)
            else:
                break
        if f and not f.closed:
            f.close()

    def upload_file(self, bucket, keyname, filename):
        """
        Handles the actual file upload, either monolithic or multipart
        """

        # Include the file system metadata so that we have the
        # option of using it to restore the file modes correctly.
        stat = get_fs_meta(filename)
        if not stat:
            return

        # Already uploaded this file, skip it
        if self.key_exists(bucket, keyname, filename, stat):
            return
        else:
            fp = open(filename, 'rb')
            md5 = boto.utils.compute_md5(fp)
            self.log.debug('Computed md5sum before upload is: %s' % (md5,))
            fp.close()

        def progress(sent, total):
            "Progress callback"

            if sent == total:
                self.log.info('Finished uploading %s' % filename)

        try:
            self.log.info('Uploading %s' % filename)

            for r in range(self.retries):
                try:
                    self.log.debug(
                        'File size check: %s > %s ? : %s' % (
                            stat['size'], self.max_size,
                            (stat['size'] > self.max_size),
                        )
                    )
                    if stat['size'] > self.max_size:
                        self.log.info('Performing multipart upload for %s' %
                                     (filename))
                        mp = bucket.initiate_multipart_upload(
                            keyname,
                            metadata={'stat': stat, 'md5sum': md5[0]}
                        )
                        part = 1
                        chunk = None
                        try:
                            for chunk in self.split_file(filename):
                                self.log.debug(
                                    'Uploading part #%d (size: %d)' % (
                                        part, chunk.len,
                                    )
                                )
                                mp.upload_part_from_file(chunk, part)
                                chunk.close()
                                part += 1
                            part -= 1
                        except Exception as e:
                            self.log.debug(e)
                            self.log.info('Error uploading part %d' % (part,))
                            mp.cancel_upload()
                            if chunk:
                                chunk.close()
                            raise
                        self.log.debug('Uploaded %d parts, '
                                       'completing upload' % (part,))
                        mp.complete_upload()
                        progress(100, 100)
                    else:
                        self.log.debug('Performing monolithic upload')
                        key = bucket.new_key(keyname)
                        key.set_metadata('stat', stat)
                        key.set_metadata('md5sum', md5[0])
                        key.set_contents_from_filename(filename, replace=True,
                                                       cb=progress, num_cb=1,
                                                       md5=md5)
                    break
                except:
                    if not os.path.exists(filename):
                        # File was removed? Skip
                        return

                    if r == self.retries - 1:
                        self.log.critical('Failed to upload file contents.')
                        raise

                    # Might have lost connection, reconnect
                    bucket = self._bucket()
                    continue

        except:
            self.log.error('Error uploading %s\n%s' % (keyname, traceback.format_exc()))
            raise

    def worker(self):
        """
        Main threading.Thread method
        """

        while True:
            filename, track = self.fileq.get()
            if track:
                snapshot = base.get_dir_snapshot(self.paths, self.recurse, self.include)
            keyname = '%s%s%s' % (self.prefix, self.name, filename)
            self.log.debug('Key is %s' % (keyname,))
            try:
                self.upload_file(self._bucket(), keyname, filename)
                if track and not self.without_index:
                    save_snapshot(snapshot)
            except:
                self.log.critical(
                    'Failed uploading %s. Aborting.\n%s' % (
                        filename, traceback.format_exc()
                    )
                )
                # Brute force kill self
                os.kill(os.getpid(), signal.SIGKILL)

            self.fileq.task_done()


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Tablesnap is a script that '
        'uses inotify to monitor a directory for events and reacts to them by '
        'spawning a new thread to upload that file to Amazon S3, along with '
        'a JSON-formatted list of what other files were in the directory at '
        'the time of the copy.'
    )
    parser.add_argument('bucket', help='S3 bucket')
    parser.add_argument('paths', metavar='path', nargs='+', help='Path(s) to be watched')
    parser.add_argument(
        '-k', '--aws-key', required=not os.environ.get('AWS_ACCESS_KEY_ID', False),
        help='Your AWS key id, defaults to ENV[AWS_ACCESS_KEY_ID] if set',
        default=os.environ.get('AWS_ACCESS_KEY_ID')
    )
    parser.add_argument(
        '-s', '--aws-secret', required=not os.environ.get('AWS_SECRET_ACCESS_KEY', False),
        help='Your AWS key secret, defaults to ENV[AWS_SECRET_ACCESS_KEY] if set',
        default=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    parser.add_argument(
        '-r', '--recursive', action='store_true', default=False,
        help='Recursively watch the given path(s)s for new SSTables'
    )
    parser.add_argument(
        '-a', '--auto-add', action='store_true', default=False,
        help='Automatically start watching new subdirectories within path(s)'
    )
    parser.add_argument(
        '-p', '--prefix', default='',
        help='Set a string prefix for uploaded files in S3'
    )
    parser.add_argument(
        '-t', '--threads', default=base.DEFAULT_THREADS, type=int,
        help='Number of writer threads'
    )
    parser.add_argument(
        '-n', '--name', default=socket.getfqdn(),
        help='Use this name instead of the FQDN to identify the files from this host'
    )
    parser.add_argument(
        '--md5-on-start', default=False, action='store_true',
        help='If you want to compute *every file* for its MD5 checksum at '
             'start time, enable this option.'
    )
    parser.add_argument(
        '-R', '--retries', default=DEFAULT_RETRIES, type=int,
        help='Default times to retry on all S3 operations'
    )
    parser.add_argument(
        '-l', '--listen-events', action='append',
        choices=LISTEN_EVENTS,
        default=DEFAULT_LISTEN_EVENTS,
        help='Which events to listen on, can be specified multiple times. '
             'Values: %s' % (','.join(LISTEN_EVENTS))
    )
    mode_choices = [
        'daemon',
        'singlepass',
        'singlefile',
    ]
    parser.add_argument(
        '-m', '--mode', choices=mode_choices,
        default='daemon',
        help='What mode you want to start tablesnap in'
    )

    include_group = parser.add_mutually_exclusive_group()
    include_group.add_argument(
        '-e', '--exclude', default=None,
        help='Exclude files matching this regular expression from upload.'
             'WARNING: If neither exclude nor include are defined, then all '
             'files matching "-tmp" are excluded.'
    )
    include_group.add_argument(
        '-i', '--include', default=None,
        help='Include only files matching this regular expression into upload.'
             'WARNING: If neither exclude nor include are defined, then all '
             'files matching "-tmp" are excluded.'
    )

    parser.add_argument(
        '--max-upload-size', default=DEFAULT_MAX_FILE_SIZE, type=int,
        help='Max size (in Mb) for files before doing multipart upload'
    )
    parser.add_argument(
        '--multipart-chunk-size', default=DEFAULT_CHUNK_SIZE, type=int,
        help='Chunk size (in Mb) for multipart uploads (%dMb or 10%%%% of '
             'free memory)' % DEFAULT_CHUNK_SIZE
    )
    parser.add_argument(
        '--without-index', default=False, action='store_true',
        help='Skip adding a directory listing file per file backed up'
    )

    args = parser.parse_args()

    # File filtering
    include = DEFAULT_INCLUDE
    if args.exclude:
        include = lambda path: not re.search(args.exclude, path)
    if args.include:
        include = lambda path: re.search(args.include, path)

    # Check S3 credentials only. We reconnect per-thread to avoid any
    # potential thread-safety problems.
    s3 = base.s3_connect(args.aws_key, args.aws_secret, DEBUG)
    assert s3

    handler = UploadHandler(
        key=args.aws_key,
        secret=args.aws_secret,
        bucket_name=args.bucket,
        prefix=args.prefix,
        name=args.name,
        threads=args.threads,
        include=include,
        log=LOGGER,
        max_size=int(args.max_upload_size),
        chunk_size=int(args.multipart_chunk_size),
        md5_on_start=args.md5_on_start,
        debug=DEBUG,
        retries=args.retries,
        without_index=args.without_index,
        recurse=args.recurse,
    )

    LOGGER.info('Starting up in %s mode' % (args.mode,))

    if args.mode == 'daemon':
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, handler)

        mask = get_mask(args.listen_events)
        for path in args.paths:
            ret = wm.add_watch(path, mask, rec=args.recursive,
                               auto_add=args.auto_add)
            if ret[path] == -1:
                LOGGER.critical('add_watch failed for %s, bailing out!' % (path))
                return 1

        backup_files(handler, args.paths, args.recursive, include)
        notifier.loop()
    elif args.mode == 'singlepass':
        backup_files(handler, args.paths, args.recursive, include)
    elif args.mode == 'singlefile':
        for p in args.paths:
            if not os.path.isfile(p):
                LOGGER.warning(
                    'When using "onefile" you have to point to files, '
                    'not directories. Skipping %s' % (p,)
                )
                continue
            filename = os.path.basename(p)
            path = os.path.dirname(p)
            backup_file(handler, filename, include)
    else:
        pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
