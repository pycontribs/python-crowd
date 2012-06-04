from setuptools import setup

setup(
    name='Crowd',
    license='GPL v3',
    py_modules=['crowd',],
    version='0.1dev',

    description = 'A python client to the Atlassian Crowd REST API',
    long_description=open('README.md').read(),

    author = 'Alexander Else',
    author_email = 'aelse@else.id.au',
    url = 'https://github.com/aelse/python-crowd',
)
