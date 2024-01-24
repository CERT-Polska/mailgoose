#!/usr/bin/env python

import os
from distutils.core import setup

with open(os.path.join(os.path.dirname(__file__), "requirements.txt")) as f:
    requires = f.read().splitlines()


setup(
    name="libmailgoose",
    version="1.0",
    description="libmailgoose - check the settings needed to protect against e-mail spoofing",
    author="CERT Polska",
    author_email="info@cert.pl",
    url="https://github.com/CERT-Polska/mailgoose",
    packages=["libmailgoose"],
    scripts=[],
    install_requires=requires,
)
