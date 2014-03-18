#!/usr/bin/env python
#
# -*- mode:python; sh-basic-offset:4; indent-tabs-mode:nil; coding:utf-8 -*-
# vim:set tabstop=4 softtabstop=4 expandtab shiftwidth=4 fileencoding=utf-8:
#

import setuptools
import sys

import table


install_requires = [
    _.strip()
    for _ in open('requirements.txt').readlines()
    if _ and not _.startswith('#')
]

# only required when you are doing testing
test_requires = [
    'moto',
    'pep8',
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
    packages=setuptools.find_packages('table'),
    package_dir={
        '': 'table',
    },
    license='BSD',
    install_requires=install_requires,
    zip_safe=False,
    test_suite='tests.all.test_suites',
)
