#!/usr/bin/env python
from setuptools import setup

setup(
    name="poectrl",
    version="0.1.0",
    author="Fredrik Strupe",
    author_email="fredrik@strupe.net",
    url="https://github.com/frestr/poectrl",
    description="Power-over-Ethernet (PoE) Port Control for LGS3XXP Switches",
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
    python_requires=">=3.6.0",
    install_requires=[
        "beautifulsoup4==4.12.3",
        "lxml==5.1.0",
        "pycryptodome==3.20.0",
        "PyYAML==6.0.1",
        "requests==2.31.0",
        "urllib3==1.26.5",
    ],
    packages=["poectrl"],
    entry_points={
        "console_scripts": ["poectrl=poectrl.main:main"],
    },
)
