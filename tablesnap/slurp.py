#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import argparse
import grp
import threading
import os
import pwd
import socket
import sys

from . import base


# Setup logging and debugging levels
LOGGER, DEBUG = base.set_logger('tableslurp')


class DownloadCounter(object):
    attemptcount = 0

    def __init__(self, filename=None):
        self.filename = filename

    def increment(self):
        self.attemptcount += 1


class DownloadHandler(object):

    def __init__(
        self,
        target,
        origin,
        aws_key,
        aws_secret,
        bucket_name,
        owner,
        group,
        preserve=False,
        threads=base.DEFAULT_THREADS,
        force=False,
        name=socket.getfqdn(),
        prefix='',
        log=LOGGER,
    ):

        self.target = target
        self.origin = origin
        self.preserve = preserve
        self.key = aws_key
        self.secret = aws_secret
        self.bucket_name = bucket_name
        self.num_threads = threads
        self.force = force
        self.name = name
        self.prefix = prefix
        self.log = log

        try:
            self.owner = pwd.getpwnam(owner).pw_uid
            self.group = grp.getgrnam(group).gr_gid
        except Exception as e:
            self.log.error(e)
            raise OSError(
                'User/Group pair %s:%s does not exist' % (
                    owner, group,
                )
            )

    def _bucket(self):
        """
        Returns a new bucket connected to s3
        """

        self.log.debug('Connecting to s3')
        return base.get_bucket(
            base.s3_connect(
                self.key, self.secret, self.debug
            ), self.bucket_name
        )
        self.log.debug('Connected to s3')

    def _build_file_set(self, target_file=None):
        pass
#        self.log.info('Building fileset')
#        key = None
##       If you want to restore a file-set in particular
#        bucket = self._get_bucket()
#        if target_file:
#            key = bucket.get_key(
#                '%s/%s-listdir.json' % (
#                    self.prefix, target_file
#                )
#            )
##       Otherwise try to fetch the most recent one
#        else:
#            keys = [_ for _ in bucket.list(prefix='%s/' %
#                (self.prefix,)) if _.name.endswith('-listdir.json')]
#            if keys:
#                keys.sort(key=lambda l: parser.parse(l.last_modified))
#                key = keys.pop()
#
#        if not key:
#            raise LookupError('Cannot find anything to restore from %s:%s/%s' %
#                (bucket.name, self.prefix, target_file or ''))
#
#        json_data = json.loads(key.get_contents_as_string())
#        self.fileset = json_data[self.origin]
#        self.log.info('Fileset contains %d files to download' % (len(self.fileset)))
#        k = bucket.get_key('%s/%s' % (self.prefix, self.fileset[0]))
##       The librato branch introduced this
#        meta = k.get_metadata('stat')
#        self.log.debug('Metadata is %s' % (meta,))
#        owner = None
#        group = None
#        if meta:
#            try:
#                json_data = json.loads(meta)
#                owner = json_data['user']
#                group = json_data['group']
#            except TypeError as te:
#                self.log.debug(te)
#                self.log.warning('Could not parse stat metadata for %s' % (k.name,))
#            except KeyError as ke:
#                self.log.debug(ke)
#                self.log.warning('Incomplete stat metadata for %s, will ignore' %
#                    (k.name,))
#        return (owner, group)

    def _test_permissions(self):
        self.log.info(
            'Will now try to test writing to the target dir %s' % (
                self.target,
            )
        )
        try:

            if not os.path.isdir(self.target):
                self.log.debug('Creating temp file in %s' % (self.target,))
                os.makedirs(self.target)
            self.log.debug(
                'Changing owner:group for %s to %s:%s' % (
                    self.target, self.owner, self.group,
                )
            )

            os.chown(self.target, self.owner, self.group)
        except Exception as e:
            self.log.debug(e)
            self.log.exception('%s exists' % (self.target,))
        self.log.info('Will write to %s' % (self.target,))

    def _worker(self, idx, queue):
        self.log.info('Thread #%d processing items' % (idx, ))
        bucket = self._get_bucket()

        while not queue.empty():
            queueddownload = queue.get()
            fname = queueddownload.filename
            keypath = '%s/%s' % (self.prefix, fname,)
            destfile = os.path.join(self.target, os.path.basename(fname))

            self.log.debug(
                'Checking if we need to download %s to %s' % (
                    keypath, destfile,
                )
            )

            if queueddownload.attemptcount < 5:
                download = False
                #Retry downloading until we succeed
                try:
                    key = bucket.get_key(keypath)
                    self.log.debug('Key objectd is %s' % key)
                    if os.path.isfile(destfile):
                        stat = os.stat(destfile)
                        if self.force:
                            download = True
                        elif stat.st_size != key.size:
                            self.log.info(
                                '%s and %s size differs, will re-download' % (
                                    key.name, destfile,
                                )
                            )
                            download = True
                    else:
                        download = True

                    if download:
                        self.log.info(
                            'Downloading %s from %s to %s' % (
                                key.name, bucket.name, destfile,
                            )
                        )
                        key.get_contents_to_filename(destfile)

                except Exception as e:
                    self.log.debug(e)
                    self.log.exception('Failed to download `%s` retrying' % (fname,))
                    #We can't download, try again
                    queueddownload.increment()
                    queue.put(queueddownload)

            else:
                self.log.info('Tried to download %s too many times. Giving up' % (fname,))

            #Pop the task regardless of state.  If it fails we've put it back
            queue.task_done()

        self.log.info('Thread #%d finished processing' % (idx,))

    def run(self):
        self._test_permissions()
        self.log.info('Running')

        #queue up the filesets
        for filename in self.fileset:
            self.log.info('Pushing file %s onto queue' % filename)
            self.queue.put(DownloadCounter(filename))

#       launch threads and attach an event to them
        for idx in range(0, self.num_threads):
            self.threads[idx] = {}
#            e = threading.Event()
            t = threading.Thread(
                target=self._worker,
                kwargs={
                    'idx': idx,
                    'queue': self.queue
                }
            )
            t.setDaemon(True)
            self.threads[idx] = t
            t.start()

        #Wait for everything to finish downloading
        self.queue.join()
        self.log.info('My job is done.')


def main():
    owner = pwd.getpwnam(os.environ['USER']).pw_name
    group = grp.getgrnam(os.environ['USER']).gr_name
    ap = argparse.ArgumentParser(
        description='This is the companion script to the `tablesnap` program '
        'which you can use to restore files from an Amazon S3 bucket to any '
        'given local directory which you have write-permissions on. While the '
        'code is straightforward, the program assumes the files you are '
        'restoring got previously backed up with `tablesnap`',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument(
        '-k', '--aws-key', required=not os.environ.get('AWS_ACCESS_KEY_ID', False),
        help='Your AWS key id, defaults to ENV[AWS_ACCESS_KEY_ID] if set',
        default=os.environ.get('AWS_ACCESS_KEY_ID')
    )
    ap.add_argument(
        '-s', '--aws-secret', required=not os.environ.get('AWS_SECRET_ACCESS_KEY', False),
        help='Your AWS key secret, defaults to ENV[AWS_SECRET_ACCESS_KEY] if set',
        default=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    ap.add_argument(
        '-p', '--preserve', default=False, action='store_true',
        help='Preserve the permissions (if they exist) from the source. '
        'This overrides -o and -g'
    )
    ap.add_argument(
        '-o', '--owner', default=owner,
        help='After download, chown files to this user.'
    )
    ap.add_argument(
        '-g', '--group', default=group,
        help='After download, chgrp files to this group.'
    )
    ap.add_argument(
        '-t', '--threads', type=int, default=base.DEFAULT_THREADS,
        help='Split the download between this many threads'
    )
    ap.add_argument(
        '--force', default=False, action='store_true',
        help='Force download files even if they exist'
    )
    ap.add_argument(
        '-n', '--name', default=socket.getfqdn(),
        help='Use this name instead of the FQDN to prefix the bucket dir'
    )
    ap.add_argument(
        'bucket', nargs=1,
        help='S3 bucket to download files from'
    )
    ap.add_argument(
        'origin', nargs=1,
        help='Path inside the bucket to the directory you want to download '
        'files from'
    )
    ap.add_argument(
        'target', nargs=1,
        help='Path in the local FS where files should be downloaded to'
    )
    args = ap.parse_args()

    dh = DownloadHandler(
        target=args.target.pop(),
        origin=args.origin.pop(),
        aws_key=args.aws_key,
        aws_secret=args.aws_secret,
        bucket_name=args.bucket.pop(),
        owner=args.owner,
        group=args.group,
        preserve=args.preserve,
        threads=args.threads,
        force=args.force,
        name=args.name,
        prefix=args.prefix,
        log=LOGGER,
    )

    dh.run()

if __name__ == '__main__':
    sys.exit(main())
