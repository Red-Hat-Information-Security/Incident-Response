# Red Hat Information Risk and Security

## Incident Response Tools

### ioc-check.py

Check for host IoCs and malicious packages covered in [these files](https://github.com/Red-Hat-Information-Security/Incident-Response/tree/main/data).

Usage:

- Download the script
- Then run:
  ```
  chmod +x ioc-check.py
  ./ioc-check.py
  ```

#### Example output (no findings):

```
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. This script looks indicators of compromise listed
in:

https://github.com/Red-Hat-Information-Security/Incident-Response/tree/main/data
===============================================================================

WARNING: On Mac you may be asked to provide your terminal program access to
other parts of the system. This script attempts to scan the whole system, this
is why you are seeing these requests. The scan will be more effective with
access to the whole system.

Fetching RHIS malicious package db...
Loading RHIS malicious package db...
Fetching RHIS Host IoC db...
Loading RHIS Host IoC db...
Scanning for Indicators of Compromise (IoCs)...

[PHEW] No malicious packages found
```

#### Example output (with findings):

```

===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. This script looks indicators of compromise listed
in:

https://github.com/Red-Hat-Information-Security/Incident-Response/tree/main/data
===============================================================================

WARNING: On Mac you may be asked to provide your terminal program access to
other parts of the system. This script attempts to scan the whole system, this
is why you are seeing these requests. The scan will be more effective with
access to the whole system.

Fetching RHIS malicious package db...
Loading RHIS malicious package db...
Fetching RHIS Host IoC db...
Loading RHIS Host IoC db...
Scanning for Indicators of Compromise (IoCs)...

[WARNING] Malicious Package IoC(s) Found:

- Finding: Malicious Package: pkg:npm/axios@0.30.4
  Notes: Campaign(s): TeamPCP supply chain attack
  Location: /path/to/package.json

[IMPORTANT] Please include the following in your ticket to InfoSec:

- ALL OF THE SCRIPT OUTPUT ABOVE
- Username: user
- Hostname: host
- Timestamp: 1775506415
```

#### Disclaimer

There may be new packages that haven't been added to the data sets yet.

## Maintenance Note

For those working on this project you can run `make sync` to refresh the OSSF
malicious package listing in the repo and commit the changes. We are working
from a snapshot of the repo instead of cloning it fresh to each person's
machine since the repo has gotten huge and can cause clone issues. Also it's
nice to remove the git dependency in the script.
