#!/usr/bin/env python

import os
from distutils.core import setup

with open(os.path.join(os.path.dirname(__file__), "requirements.txt")) as f:
    requires = f.read().splitlines()


setup(
    name="libmailgoose",
    version="1.2",
    description="libmailgoose - check the settings needed to protect against e-mail spoofing",
    author="CERT Polska",
    author_email="info@cert.pl",
    license="BSD",
    url="https://github.com/CERT-Polska/mailgoose",
    packages=["libmailgoose"],
    scripts=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
    ],
    install_requires=requires,
)
