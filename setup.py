#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import os
import setuptools
import sys

import table


readme = os.path.join(os.path.dirname(sys.argv[0]), 'README.md')
reqs = os.path.join(os.path.dirname(sys.argv[0]), 'requirements.txt')
test_reqs = os.path.join(os.path.dirname(sys.argv[0]), 'test-requirements.txt')

install_requires = [
    _.strip()
    for _ in open(reqs).readlines()
    if _ and not _.startswith('#')
]

# only required when you are doing testing
test_requires = [
    _.strip()
    for _ in open(test_reqs).readlines()
    if _ and not _.startswith('#')
]

args = sys.argv[1:]
# if we are installing just punt all extra reqs and do install_requires only
if 'install' not in args:
    for arg in args:
        if arg == 'test':
            install_requires.extend(test_requires)
            continue

setuptools.setup(
    name='tablesnap',
    version=table.__version__,
    author='Jeremy Grosser',
    author_email='jeremy@synack.me',
    description='Uses inotify to monitor Cassandra SSTables and upload them to S3',
    long_description=open(readme).read(),
    keywords=[
        'cassandra',
        'inotify',
        'backup',
    ],
    packages=setuptools.find_packages('table'),
    package_dir={
        '': 'table',
    },
    license='BSD',
    install_requires=install_requires,
    zip_safe=False,
    test_suite='tests.all.test_suites',
)
