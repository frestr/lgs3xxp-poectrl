#!/usr/bin/env python
from setuptools import setup

setup(
    name="poectrl",
    version="1.0.0",
    author="Fredrik Strupe",
    author_email="fredrik@strupe.net",
    url="https://github.com/frestr/poectrl",
    description="Power-over-Ethernet Control for LGS3XXP Switches",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Programming Language :: Python",
    ],
    packages=["poectrl"],
    entry_points={
        "console_scripts": ["poectrl=poectrl.main:main"],
    },
)
