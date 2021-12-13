# appknox-go [![CircleCI](https://circleci.com/gh/appknox/appknox-go.svg?style=svg)](https://circleci.com/gh/appknox/appknox-go) [![codecov](https://codecov.io/gh/appknox/appknox-go/branch/develop/graph/badge.svg)](https://codecov.io/gh/appknox/appknox-go)
Command-line interface for Appknox API written in go

## Usage

```
$ appknox

A CLI tool to interact with appknox api

Usage:
  appknox [command]

Available Commands:
  analyses      List analyses for file
  cicheck       Check for vulnerabilities based on risk threshold.
  files         List files for project
  help          Help about any command
  init          Used to initialize Appknox CLI
  organizations List organizations
  owasp         Fetch OWASP by ID
  projects      List projects
  upload        Upload and scan package
  vulnerability Get vulnerability
  whoami        Shows current authenticated user

Flags:
  -a, --access-token string   Appknox Access Token
  -h, --help                  help for appknox
      --host string           Appknox Server (default "https://api.appknox.com/")
  -k, --insecure              Disable Security Checks
      --pac string            pac file path or url
      --proxy string          proxy url
      --version               version for appknox

Use "appknox [command] --help" for more information about a command.
```

### Authentication

CLI requires an access_token to interact with Appknox API.
To initialize the token to use any of the available commands
please run the following command:

```
$ appknox init
Please put the APPKNOX_ACCESS_TOKEN value below.
✔ Access Token: █
```

Get the access_token from the Appknox dashboard developer settings and put it to the prompt.

#### Using Environment Variables

Instead of init command we can use environment variables for authentication. This will be useful for scenarios such as CI/CD setup.

```
export APPKNOX_ACCESS_TOKEN=1a0b61a6f6f3548f04540a18c49bd40759879c73
```

For CI/CD in on-premise installations, change the Appknox host value:

```
export APPKNOX_API_HOST=https://customdomain.onpremisecompany.com/
```

#### Using command flags

We can also pass the value of access-token with the command we are running:

E.g.:
```
$ appknox whoami --access-token 1a0b61a6f6f3548f04540a18c49bd40759879c73

ID:         123
Username:   abc
Email:      abc@abc.com
```

Note that this method will not set the access_token permanently which means that
each time you run a command you have to pass the flag `access-token`.

### Data fetch & actions

| Available commands | Use |
|--------------------|-----|
| `organizations` | List organizations of user |
| `projects` | List projects user has access to |
| `files <project_id>` | List files for a project |
| `analyses <file_id>` | List analyses for a file |
| `vulnerability <vulnerability_id>` | Get vulnerability detail |
| `owasp <owasp_id>` | Get OWASP detail |
| `upload <path_to_app_package>` | Upload app file from given path and get the file_id |
| `cicheck <file_id>` | Check for vulnerabilities based on risk threshold. |

## Example:

```
$ appknox organizations

ID:              1
Username:        DemoOrg
ProjectsCount:   2

$ appknox projects
  id  created_on             file_count  package_name                     platform  updated_on
----  -------------------  ------------  -----------------------------  ----------  -------------------
   3  2017-06-23 07:19:26             3  org.owasp.goatdroid.fourgoats           0  2017-06-23 07:26:55
   4  2017-06-27 08:27:54             2  com.appknox.mfva                        0  2017-06-27 08:30:04

$ appknox files 4
  id  name      version    version_code
----  ------  ---------  --------------
   6  MFVA            1               6
   7  MFVA            1               6

- **Upload a file and do cicheck based on the risk threshold**

$ appknox upload ~/Downloads/mfva.apk | xargs appknox cicheck --risk-threshold low

2.3 MiB / 2.3 MiB [==========================================================| 00:00 ] 226.28 KiB/s
Static Scan Progress:  100 % [==========================================================| ]
Found vulnerabilities with risk threshold greater or equal than the provided: Low

ID      RISK    CVSS-VECTOR                                   CVSS-BASE  VULNERABILITY-ID  VULNERABILITY-NAME
--      ----    -----------                                   ---------  ----------------  ------------------
671660  High    CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L  7.3        2                 Improper Content Provider Permissions
671637  High    CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H  7.7        3                 Application Debugging
671635  Low     CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N  2.3        10                Unused Permissions
671664  High    CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L  8.6        16                Derived Crypto Keys
671652  Medium  CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  6.2        17                Application Logs
671642  High    CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H  8.1        37                Connection to External Redis Server
671607  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        39                Unprotected Exported Receivers
671601  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        40                Unprotected Exported Service
671603  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        42                Non-signature Protected Exported Activities
671653  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        43                Non-signature Protected Exported Receivers
671620  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        44                Non-signature Protected Exported Services
671626  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        45                Non-signature Protected Exported Providers
671606  Medium  CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N  5.9        83                Disabled SSL CA Validation and Certificate Pinning
671658  Medium  CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N  6.8        92                MediaProjection: Android Service Allows Recording of Audio, Screen Activity
671600  Low     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N  3.3        96                Enabled Android Application Backup

exit status 1

```
