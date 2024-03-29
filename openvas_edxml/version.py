# Store the version here so:
# 1) we don't load dependencies by storing it in __init__.py
# 2) we can import it in setup.py for the same reason
# 3) we can import it into your module module
#
# Version 3.0.0:
__version_info__ = ('3', '0', '0')
__version__ = '.'.join(__version_info__)
