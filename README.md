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
in https://github.com/ossf/malicious-packages with specific versions listed.
===============================================================================

Fetching malicious package db...
Loading malicious package set...
Scanning installed npm packages...
No malicious packages found
```

#### Example output (with findings):

```
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. It's meant to be a basic check against packages
in https://github.com/ossf/malicious-packages with specific versions listed.
===============================================================================


Fetching malicious package db...
Loading malicious package set...
Scanning installed npm packages...
@operato/headroom@9.0.35 -> /run/host/home/youruser/example/package.json
```

#### Disclaimer
This is based on the OSSF's malicious packages repo and as of this moment it doesn't seem like they have every version listed in the blog posts above.
