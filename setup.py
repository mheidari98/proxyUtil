#!/usr/bin/env python3
# -*- coding=utf-8 -*-

from os import path
from setuptools import find_namespace_packages, setup

proj_dir = path.dirname(path.realpath(__file__))
about_file = path.join(proj_dir, "proxyUtil", "__version__.py")
readme_file = path.join(proj_dir, "README.md")

about = {}
exec(open(about_file, "r", encoding="utf-8").read(), about)

long_description = open(readme_file, "r", encoding="utf-8").read()

requirements = open("requirements.txt", "r", encoding="utf-8").read().splitlines()

setup(
    name=about["__title__"],
    version=about["__version__"],

    author=about["__author__"],
    author_email=about["__author_email__"],

    description=about["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",

    url=about["__url__"],

    license=about["__license__"],

    #packages=find_packages(), # ['proxyUtil']
    packages=find_namespace_packages(exclude=["scripts"]),

    include_package_data=True,
    #package_data={'': ['data/*']},

    install_requires=requirements,
    
    extras_require={
        "dev": [
            "pytest >= 3.7",
            "twine"
        ]
    },
    
    scripts=[ 
        path.join("scripts", "clashGen"),  # scripts/clashGen
        path.join("scripts", "connectMe"),
        path.join("scripts", "shadowChecker"),
        path.join("scripts", "sslocal2ssURI"),
        path.join("scripts", "ssURI2sslocal"),
    ],

    entry_points={
        "console_scripts": [
            "cdnGen = proxyUtil.cdnGen:main",
            "dnsChecker = proxyUtil.dnsChecker:main",
            "cfRecorder = proxyUtil.cfRecorder:main",
            "ipExtractor = proxyUtil.ipExtractor:main",
            "v2rayChecker = proxyUtil.v2rayChecker:main",
        ]
    },
    
    classifiers=[
        # https://pypi.org/classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',  
        'Operating System :: POSIX :: Linux',        
        "Programming Language :: Python :: 3",
    ],

    python_requires='>=3',
)
