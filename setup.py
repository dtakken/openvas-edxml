from setuptools import setup, find_packages

# Explicitly state a version to please flake8
__version__ = 1.0
# This will read __version__ from edxml/version.py
exec(open('openvas_edxml/version.py').read())

setup(
    name='openvas-edxml',
    version=__version__,

    # A description of your project
    description='An OpenVAS XML to EDXML transcoder',
    long_description='EDXML transcoder that takes OpenVAS XML reports as input and outputs EDXML data',

    # The project's main homepage
    url='https://github.com/dtakken/edxml-openvas',

    # Author details
    author='Dik Takken',
    author_email='d.h.j.takken@freedom.nl',

    # Choose your license
    license='MIT',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3'
    ],

    # What does your project relate to?
    keywords='edxml openvas',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=[]),

    # Add entry points which will be installed as CLI utilities
    entry_points={
        'console_scripts': ['openvas-edxml=openvas_edxml/cli:main'],
    },
    # List run-time dependencies here. These will be installed by pip when your
    # project is installed.
    # See https://pip.pypa.io/en/latest/reference/pip_install.html#requirements-file-format
    # For an analysis of "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/en/latest/technical.html#install-requires-vs-requirements-files
    install_requires=[
        'edxml>=3.0.0.dev0',
        'edxml-bricks-generic>=3.0.0.dev0',
        'edxml-bricks-geography>=3.0.0.dev0',
        'edxml-bricks-computing>=3.0.0.dev0',
        'edxml-bricks-computing-networking>=3.0.0.dev0',
        'edxml-bricks-computing-security>=3.0.0.dev0',
        'cryptography',
        'edxml-bricks-computing-forensics>=3.0.0.dev0',
        'IPy',
        'python-dateutil'
    ]
)
