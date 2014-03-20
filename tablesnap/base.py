#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import logging
import os


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
