import os
from setuptools import setup, find_packages
import versioneer

# vagrant doesn't appreciate hard-linking
if os.environ.get('USER') == 'vagrant' or os.path.isdir('/vagrant'):
    del os.link

setup(
    name="csirtg_indicator",
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="CSIRTG Indicator Framework",
    long_description="",
    url="https://github.com/csirtgadgets/csirtg-indicator-py",
    license='LGPL3',
    classifiers=[
               "Topic :: System :: Networking",
               "Environment :: Other Environment",
               "Intended Audience :: Developers",
               "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
               "Programming Language :: Python",
               ],
    keywords=['network', 'security'],
    author="Wes Young",
    author_email="wes@csirtgadgets.org",
    packages=find_packages(),
    install_requires=[
        'arrow==0.7.0',
        'pytest==2.9.1',
        'pytricia==0.9.0',
        'ipaddress==1.0.16',
        'pytest-cov==2.2.1',
        'pendulum==0.5.2',
        'prettytable==0.7.2'
    ],
    scripts=[],
    entry_points={
       'console_scripts': [
           'csirtg-indicator=csirtg_indicator.indicator:main',
       ]
    },
)
