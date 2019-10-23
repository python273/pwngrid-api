#!/usr/bin/env python
from io import open
from setuptools import setup

version = "0.0.1"

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pwngrid-api",
    version=version,
    author="python273",
    author_email="pwngrid@python273.pw",
    description="Pwnagotchi's Pwngrid API client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/python273/pwngrid-api",
    download_url="https://github.com/python273/pwngrid-api/archive/v{}.zip".format(
        version
    ),
    license="MIT",
    packages=["pwngrid_api"],
    install_requires=["requests", "cryptography"],
    extras_require={},
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
)
