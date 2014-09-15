#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import sys
import unittest

import util
assert util


def test_cases():
    pass


def main():
    util.create_random_files('/tmp/foo', ('more', ))
    #runner = unittest.TextTestRunner(verbosity=2)
    #result = runner.run(test_cases())
    #return (len(result.errors) + len(result.failures)) > 0

if __name__ == '__main__':
    sys.exit(main())
