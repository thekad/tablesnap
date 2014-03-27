#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

from __future__ import absolute_import

import boto
import logging
import multiprocessing
import os


# Default number of writer threads
DEFAULT_THREADS = multiprocessing.cpu_count()


def get_dir_snapshot(paths, recurse, include=None):
    """
    Grabs a directory listing of the given paths and returns a simple list,
    after filtering out results
    """

    filenames = []
    for path in paths:
        if recurse:
            for root, dirs, files in os.walk(path):
                for filename in files:
                    if include is None or (
                        include is not None
                        and include(filename)
                    ):
                        filenames.append(filename)
        else:
            for filename in os.listdir(path):
                if include is None or (
                    include is not None
                    and include(filename)
                ):
                    filenames.append(filename)
    return filenames


def s3_connect(key, secret, debug=0):
    s3 = boto.connect_s3(key, secret, debug=debug)
    return s3


def get_bucket(connection, bucket_name):
    # Reconnect to S3
    return connection.get_bucket(bucket_name)


def set_logger(program='tablesnap'):
    """
    Sets the default logging mechanism
    """

    log = logging.getLogger(program)
    if os.environ.get('TSYSLOG', False):
        facility = logging.handlers.SysLogHandler.LOG_DAEMON
        syslog = logging.handlers.SysLogHandler(address='/dev/log', facility=facility)
        syslog.setFormatter(logging.Formatter('tablesnap: %(message)s'))
        log.addHandler(syslog)
    else:
        stderr = logging.StreamHandler()
        stderr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        log.addHandler(stderr)

    debug = os.environ.get('TDEBUG', 0)
    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    return log, debug
