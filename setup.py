#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import os
import pip.req
import setuptools
import sys

import tablesnap


args = sys.argv[1:]
reqs = 'requirements.txt'

for arg in args:
    if arg == 'test':
        reqs = 'test-requirements.txt'

readme = os.path.join(os.path.dirname(sys.argv[0]), 'README.rst')
reqs = os.path.join(os.path.dirname(sys.argv[0]), reqs)

install_requires = pip.req.parse_requirements(reqs)
dependency_links = set([str(_.url) for _ in install_requires if _.url])
install_requires = set([str(_.req) for _ in install_requires])

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
    dependency_links=dependency_links,
    install_requires=install_requires,
    zip_safe=False,
    test_suite='tests.all.test_suites',
)
