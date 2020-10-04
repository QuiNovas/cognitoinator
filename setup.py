import io
from setuptools import setup


setup(
    name="cognitoinator",
    version="0.0.15",
    description="The swiss army knife of cognito authentication",
    author="Mathew Moon",
    author_email="mmoon@quinovas.com",
    url="https://github.com/QuiNovas/cognito-assume-role",
    license="Apache 2.0",
    long_description=io.open("README.rst", encoding="utf-8").read(),
    long_description_content_type="text/x-rst",
    packages=["cognito_assume_role"],
    package_dir={"cognitoinator": "src/cognitoinator"},
    install_requires=["boto3", "botocore", "warrant"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
    ],
)
