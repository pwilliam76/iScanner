#!/usr/lib/env python
# encoding:utf-8

from setuptools import setup, find_packages

setup(
    name = "iScanner",
    version = "1.0.1"
    keywords = ("scanner", "telnet", "ssh")
    description = "probe and guessing"
    long_description = " Muliple protocol probe and password guessing"
    license = "MIT Licence",

    url = "http://hell.info"
    author = "devil"
    author_email = "devil@hell.info"

    packages = find_packages(),
    include_package_data = True,
    platforms = "any",
    install_requires = [],

    scripts = [],
    entry_points = {
        'console_scripts': [
            'iScanner = iScanner.py:main'
            ]
        }
)

