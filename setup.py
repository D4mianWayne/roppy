#!/usr/bin/env python
from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='roppy',
    version='Beta',
    description='Pwning Toolkit',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/D4mianWayne/roppy',
    author='D4mianWayne',
    author_email='dubeyayushmanrobin@gmail.com,
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='Pwning',
    packages=find_packages(exclude=['examples']),
    python_requires='!=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4',
    install_requires=['termcolor'],
)