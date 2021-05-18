#!/usr/bin/env python3.8
import io
from setuptools import setup


setup(
    name="cognitoinator",
    version="0.2.0",
    description="Log into Cognito, assume an IAM role, directly access JWT's from your Cognito session, and use boto3 all with Cognito credentials",
    author="Mathew Moon",
    author_email="mmoon@quinovas.com",
    url="https://github.com/QuiNovas/cognitoinator",
    license="Apache 2.0",
    long_description=io.open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=["cognitoinator"],
    package_dir={"cognitoinator": "src/cognitoinator"},
    install_requires=["boto3", "botocore", "warrant"],
    scripts=["src/cognitoinator/scripts/cognito-profile-credential-fetcher"],
    include_package_data=True,
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
    ]
)
