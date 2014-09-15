#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import os
import tempfile


TOP_DIR = os.path.realpath('%s/../../' % (os.path.dirname(os.path.realpath(__file__)),))
TEST_DIR = os.path.realpath('%s/../' % (os.path.dirname(os.path.realpath(__file__)),))
SOURCE_DIR = os.path.realpath('%s/../../tablesnap' % (os.path.dirname(os.path.realpath(__file__)),))


def create_random_files(root, *args):
    """
    Creates a given number of  random files, it receives a tuple consisting
    of how many files and (optionally) a second parameter which can be a tuple
    of the same structure, this is so you can create random files in
    subdirectories recursively
    """

    print root, args
    if not os.path.isdir(root):
        print 'Creating directory %s' % root
        os.makedirs(os.path.expanduser(root))

    for arg in args:
        if isinstance(arg, tuple):
            subdir = os.path.join(root, arg[0])
            create_random_files(subdir, *arg[1:])
        if isinstance(arg, int):
            print 'Creating %d files' % arg
            for file in xrange(0, arg):
                tempfile.mkstemp(dir=root)

if __name__ == '__main__':
    create_random_files(
        '/tmp/foo',
        (
            'subdir1',
            20,
            (
                'sub-subdir1',
                10
            )
        ),
        (
            'subdir2',
            5
        ),
        30
    )
