#!/bin/bash

rm -rf dist/*

python setup.py sdist bdist_wheel
python setup.py bdist_wheel

python setup.py register -r pypitest
python setup.py sdist upload -r pypitest

