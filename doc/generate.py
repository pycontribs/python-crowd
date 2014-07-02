#!/usr/bin/env python
from os.path import join, dirname
try:
    from robot.libdoc import libdoc
except:
    def main():
        print """Robot Framework 2.7 or later required for generating documentation"""
else:
    def main():
        libdoc(join(dirname(__file__),'..','crowd.py'), join(dirname(__file__),'crowd.html'))


if __name__ == '__main__':
    main()