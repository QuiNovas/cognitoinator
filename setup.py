import io
from setuptools import setup


setup(
    name='cognito-assume-role',
    version='0.0.4',
    description='Assumes an IAM role in boto3 using Cognito credentials',
    author='Mathew Moon',
    author_email='mmoon@quinovas.com',
    url='https://github.com/QuiNovas/cognito-assume-role',
    license='Apache 2.0',
    long_description=io.open('README.rst', encoding='utf-8').read(),
    long_description_content_type='text/x-rst',
    packages=['cognito_assume_role'],
    package_dir={'cognito_assume_role': 'src/cognito_assume_role'},
    install_requires=['boto3', 'botocore', 'warrant'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.7',
    ],
)
