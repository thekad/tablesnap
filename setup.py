#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import os
import setuptools
import sys

import tablesnap


readme = os.path.join(os.path.dirname(sys.argv[0]), 'README.rst')
reqs = os.path.join(os.path.dirname(sys.argv[0]), 'requirements.txt')

install_requires = [
    _.strip()
    for _ in open(reqs).readlines()
    if _ and not _.startswith('#')
]

args = sys.argv[1:]
# if we are installing just punt all extra reqs and do install_requires only
if 'install' not in args:
    for arg in args:
        if arg == 'test':
            test_reqs = os.path.join(
                os.path.dirname(sys.argv[0]), 'test-requirements.txt'
            )
#           only required when you are doing testing
            test_requires = [
                _.strip()
                for _ in open(test_reqs).readlines()
                if _ and not _.startswith('#')
            ]
            install_requires.extend(test_requires)

setuptools.setup(
    name='tablesnap',
    version=tablesnap.__version__,
    author='Jeremy Grosser',
    author_email='jeremy@synack.me',
    url='https://github.com/synack/tablesnap',
    description='Uses inotify to monitor Cassandra SSTables and upload them to S3',
    long_description=open(readme).read(),
    keywords=[
        'cassandra',
        'inotify',
        'backup',
    ],
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'tablesnap=tablesnap.snap:main',
            'tableslurp=tablesnap.slurp:main',
        ],
    },
    license='BSD',
    install_requires=install_requires,
    zip_safe=False,
    test_suite='tests.all.test_suites',
)
