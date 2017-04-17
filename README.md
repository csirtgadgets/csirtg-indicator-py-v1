# Getting Started
A quick and easy way to generate threat indicator objects!

```bash
$ [sudo] pip install csirtg-indicator
$ csirtg-indicator --group everyone --indicator http://example.com/1.htm --tlp green --tags phishing
{
    "count": 1,
    "indicator": "http://example.com/1.htm",
    "itype": "url",
    "tags": [
        "phishing"
    ],
    "tlp": "green",
    "uuid": "24423bab-c81f-4819-b9be-c3d9d975a835"
}
```

# Getting Involved
There are many ways to get involved with the project. If you have a new and exciting feature, or even a simple bugfix, simply [fork the repo](https://help.github.com/articles/fork-a-repo), create some simple test cases, [generate a pull-request](https://help.github.com/articles/using-pull-requests) and give yourself credit!

If you've never worked on a GitHub project, [this is a good piece](https://guides.github.com/activities/contributing-to-open-source) for getting started.

* [the Wiki](https://github.com/csirtgadgets/csirtg-indicator-py/wiki)  
* [Known Issues](https://github.com/csirtgadgets/csirtg-indicator-py/issues?labels=bug&state=open)  
* [How To Contribute](contributing.md)  
* [Mailing List](https://groups.google.com/forum/#!forum/ci-framework)  
 

# COPYRIGHT AND LICENCE

Copyright (C) 2017 [the CSIRT Gadgets Foundation](http://csirtgadgets.org)

Free use of this software is granted under the terms of the Mozilla Public License (MPL2). For details see the file `LICENSE` included with the distribution.
