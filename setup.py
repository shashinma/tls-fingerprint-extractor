#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Setup script for JA3 Extractor package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ja3-extractor",
    version="1.0.0",
    author="Mikhail Shashin",
    description="JA3 and JA3S hash extraction from PCAP files with session grouping",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shashinma/tls-fingerprint-extractor",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ja3-extractor=ja3_extractor:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
