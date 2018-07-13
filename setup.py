from setuptools import setup, find_packages

# Explicitly state a version to please flake8
__version__ = 1.0
# This will read __version__ from edxml/version.py
exec(open('openvas_edxml/version.py').read())

setup(
    name='edxml-openvas',
    version=__version__,

    # A description of your project
    description='An OpenVAS XML to EDXML transcoder library',
    long_description='EDXML transcoder that takes OpenVAS XML reports as input and outputs EDXML data',

    # Author details
    author='Dik Takken',
    author_email='dik.takken@northwave.nl',

    # Choose your license
    license='PROPRIETARY',

    # What does your project relate to?
    keywords='edxml openvas',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=[]),

    # List run-time dependencies here. These will be installed by pip when your
    # project is installed.
    # See https://pip.pypa.io/en/latest/reference/pip_install.html#requirements-file-format
    # For an analysis of "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/en/latest/technical.html#install-requires-vs-requirements-files
    install_requires=[
        'edxml>=3.0.0.dev0',
        'edxml-bricks-generic>=3.0.0.dev0',
        'edxml-bricks-computing>=3.0.0.dev0',
        'edxml-bricks-computing-networking>=3.0.0.dev0',
        'edxml-bricks-computing-security>=3.0.0.dev0',
        'IPy',
        'python-dateutil'
    ]
)
