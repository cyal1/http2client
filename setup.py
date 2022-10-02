#!python
# -*- coding:utf-8 -*-
from __future__ import print_function
from setuptools import setup, find_packages

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name="http2client",
    version="0.1.0",
    author="cyal1",
    author_email="dsq6115119@gmail.com",
    description="A simple HTTP/2 client for Cyber Security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cyal1/http2client",
    packages=find_packages(),
    install_requires=[
        "h2 >= 2.6.2",
        "urllib3>=1.26.12",
        "setuptools"
        ],
    classifiers=[
        "Topic :: Software Development :: Libraries :: Python Modules",
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    python_requires='>=3.8'
)
