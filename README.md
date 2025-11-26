# Red Hat Information Risk and Security

## Incident Response Tools

### npm-malicious-package-check.py

Usage:
- Download the script

```
chmod +x npm-malicious-package-check.py
./npm-malicious-package-check.py
```

#### Example output (no findings):

```
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. It's meant to be a basic check against packages
in the following sources with specific versions listed:

- https://github.com/ossf/malicious-packages
- https://github.com/red-hat-information-security/incident-response
===============================================================================

Fetching OSSF malicious package db...
Loading OSSF malicious package db...
Fetching RHIS malicious package db...
Loading RHIS malicious package db...
Fetching RHIS malicious package IOC db...
Loading RHIS malicious package IOC db...
Scanning for Indicators of Compromise (IoCs)...

[PHEW] No malicious packages found
```

#### Example output (with findings):

```
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. It's meant to be a basic check against packages
in the following sources with specific versions listed:

- https://github.com/ossf/malicious-packages
- https://github.com/red-hat-information-security/incident-response
===============================================================================

Fetching OSSF malicious package db...
Loading OSSF malicious package db...
Fetching RHIS malicious package db...
Loading RHIS malicious package db...
Fetching RHIS malicious package IOC db...
Loading RHIS malicious package IOC db...
Scanning for Indicators of Compromise (IoCs)...

[WARNING] Malicious Package IoC(s) Found:

- Finding: Malicious Package: zxdb@2.0.0
  Context: Source: OSSF Malicious Package DB
  Location: /home/myuser/foo/package.json

- Finding: IoC: Malicious post-install script in node_modules directories
  Context: Campaign: Sha1-Hulud: The Second Coming
  Location: /home/myuser/foo/node_modules/foo/bun_environment.js

- Finding: Malicious Package: 02-echo@0.0.7
  Context: Campaign: Sha1-Hulud: The Second Coming
  Location: /home/myuser/bar/package.json

[IMPORTANT] Please include the following in your ticket to InfoSec:

- ALL OF THE SCRIPT OUTPUT ABOVE
- Username: myuser
- Hostname: myhost
- Timestamp: 1764186765
```

#### Disclaimer

This is based on the OSSF's malicious packages repo and a few of our own
specific package listings there may be new packages that haven't been added to
the data sets yet.


## Maintenance Note

For those working on this project you can run `make sync` to refresh the OSSF
malicious package listing in the repo and commit the changes. We are working
from a snapshot of the repo instead of cloning it fresh to each person's
machine since the repo has gotten huge and can cause clone issues. Also it's
nice to remove the git dependency in the script.
