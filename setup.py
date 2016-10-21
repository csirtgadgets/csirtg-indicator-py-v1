import os
from setuptools import setup, find_packages
import versioneer
from pip.req import parse_requirements

reqs = parse_requirements('requirements.txt')

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
    keywords=['security'],
    author="Wes Young",
    author_email="wes@csirtgadgets.org",
    packages=find_packages(),
    install_requires=reqs,
    scripts=[],
    entry_points={
       'console_scripts': [
           'csirtg-indicator=csirtg_indicator.indicator:main',
       ]
    },
)
