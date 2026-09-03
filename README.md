# appknox-go [![CircleCI](https://circleci.com/gh/appknox/appknox-go.svg?style=svg)](https://circleci.com/gh/appknox/appknox-go) [![codecov](https://codecov.io/gh/appknox/appknox-go/branch/develop/graph/badge.svg)](https://codecov.io/gh/appknox/appknox-go)
Command-line interface for Appknox API written in go

## Usage

```
$ appknox

A CLI tool to interact with appknox api

Usage:
  appknox [command]

Available Commands:
  analyses                  List analyses for file
  cicheck                   Check for vulnerabilities based on risk or health score threshold.
  files                     List files for project
  help                      Help about any command
  init                      Used to initialize Appknox CLI
  sarif                     Create SARIF report
  organizations             List organizations
  owasp                     Fetch OWASP by ID
  projects                  List projects
  reports                   Vulnerability Analysis Reports
  upload                    Upload and scan package
  vulnerability             Get vulnerability
  whoami                    Shows current authenticated user
  schedule-dast-automation  Schedules automated dynamic scan for a file
  dastcheck                 Checks the latest dynamic scan status and print dynamic vulnerabilities


Flags:
  -a, --access-token string   Appknox Access Token
  -h, --help                  help for appknox
      --host string           Appknox Server (default "https://api.appknox.com/")
  -k, --insecure              Disable Security Checks
      --pac string            pac file path or url
      --proxy string          proxy url
      --region string         Region names, e.g., global, saudi, uae. By default, global is used
      --version               version for appknox

Use "appknox [command] --help" for more information about a command.
```

## Installation
#### For Linux & macOS platform
1. Open Terminal
2. Run following command.
```
curl -L https://github.com/appknox/appknox-go/releases/download/latest/appknox-`uname -s`-x86_64 > /usr/local/bin/appknox && chmod +x /usr/local/bin/appknox
```

#### For windows platform
1. Run Powershell as Administrator
2. Run following command
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest https://github.com/appknox/appknox-go/releases/download/latest/appknox-Windows-x86_64.exe -OutFile C:\Windows\System32\appknox.exe
```

### Authentication

CLI requires an access_token to interact with Appknox API.
To initialize the token to use any of the available commands
please run the following command:

#### For Linux & macOS platform

```
$ appknox init
Please put the APPKNOX_ACCESS_TOKEN value below.
✔ Access Token: █
```

#### For windows platform

```
$ .\appknox init
Please put the APPKNOX_ACCESS_TOKEN value below.
✔ Access Token: █
```

Get the access_token from the Appknox dashboard developer settings and put it to the prompt.

#### Using Environment Variables

Instead of init command we can use environment variables for authentication. This will be useful for scenarios such as CI/CD setup.
#### For Linux & macOS platform
```
export APPKNOX_ACCESS_TOKEN=1a0b61a6f6f3548f04540a18c49bd40759879c73
```

#### For windows platform
```
$Env:APPKNOX_ACCESS_TOKEN="1a0b61a6f6f3548f04540a18c49bd40759879c73"
```

For CI/CD in on-premise installations, change the Appknox host value:
#### For Linux & macOS platform
```
export APPKNOX_API_HOST=https://customdomain.onpremisecompany.com/
```

#### For windows platform
```
$Env:APPKNOX_API_HOST="https://customdomain.onpremisecompany.com/"
```

#### Using command flags

We can also pass the value of access-token with the command we are running:

E.g.:
#### For Linux & macOS platform
```
$ appknox whoami --access-token 1a0b61a6f6f3548f04540a18c49bd40759879c73

ID:         123
Username:   abc
Email:      abc@abc.com
```

#### For windows platform
```
PATH> .\appknox whoami --access-token 1a0b61a6f6f3548f04540a18c49bd40759879c73

ID:         123
Username:   abc
Email:      abc@abc.com
```

Note that this method will not set the access_token permanently which means that
each time you run a command you have to pass the flag `access-token`.

## Data fetch & actions

| Available commands | Use |
|--------------------|-----|
| `organizations` | List organizations of user |
| `projects` | List projects user has access to |
| `files <project_id>` | List files for a project |
| `analyses <file_id>` | List analyses for a file |
| `vulnerability <vulnerability_id>` | Get vulnerability detail |
| `owasp <owasp_id>` | Get OWASP detail |
| `upload <path_to_app_package>` | Upload app file from given path and get the file_id |
| `sarif <file_id>` | Create SARIF report for the app file. |
| `cicheck <file_id>` | Check for vulnerabilities based on risk threshold or health score threshold. |
| `reports create <file_id>` | Create report for the app file |
| `reports download summary-csv <report_id>` | Download Summary CSV report for the given report of the file |
| `reports download summary-excel <report_id>` | Download Summary Excel report for the given report of the file |
| `reports download pdf <report_id>` | Download PDF report with password file |
| `schedule-dast-automation <file_id>` | Schedules Automated Dynamic Scan for a file |
| `dastcheck <file_id>` | Checks status of latest dynamic scan and print dynamic vulnerabilities upon completion |


## Example:
#### For Linux & macOS platform
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

- **Upload a file and do cicheck based on health score threshold**

$ appknox upload ~/Downloads/mfva.apk | xargs appknox cicheck --health-score-threshold 80

2.3 MiB / 2.3 MiB [==========================================================| 00:00 ] 226.28 KiB/s
Static Scan Progress:  100 % [==========================================================| ]
Health score 85 is greater than or equal to threshold 80. Build passed.

Check file ID 12345 on appknox dashboard for more details.
```

#### For windows platform
```
$ .\appknox organizations

ID:              1
Username:        DemoOrg
ProjectsCount:   2

$ .\appknox projects
  id  created_on             file_count  package_name                     platform  updated_on
----  -------------------  ------------  -----------------------------  ----------  -------------------
   3  2017-06-23 07:19:26             3  org.owasp.goatdroid.fourgoats           0  2017-06-23 07:26:55
   4  2017-06-27 08:27:54             2  com.appknox.mfva                        0  2017-06-27 08:30:04

$ .\appknox files 4
  id  name      version    version_code
----  ------  ---------  --------------
   6  MFVA            1               6
   7  MFVA            1               6

- **Upload a file and do cicheck based on the risk threshold**

$ .\appknox cicheck $(.\appknox upload .\Downloads\mfva.apk) --risk-threshold low

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

- **Upload a file and do cicheck based on health score threshold**

$ .\appknox cicheck $(.\appknox upload .\Downloads\mfva.apk) --health-score-threshold 80

2.3 MiB / 2.3 MiB [==========================================================| 00:00 ] 226.28 KiB/s
Static Scan Progress:  100 % [==========================================================| ]
Health score 85 is greater than or equal to threshold 80. Build passed.

Check file ID 12345 on appknox dashboard for more details.
```

## CI/CD Workflows

### CI Check Options

The `cicheck` command supports two modes for validating scan results:

**Risk Threshold Mode** (default):
- Use `--risk-threshold` or `-r` flag
- Options: `low`, `medium`, `high`, `critical`
- Fails if vulnerabilities with risk >= threshold are found
- Example: `appknox cicheck 12345 --risk-threshold high`

**Health Score Mode**:
- Use `--health-score-threshold` flag
- Value: 0-100 (integer)
- Passes if health score >= threshold
- Example: `appknox cicheck 12345 --health-score-threshold 80`

**Note:** You can only use one mode at a time (either `--risk-threshold` or `--health-score-threshold`, not both).

Both modes support the `--timeout` flag to set the static scan timeout in minutes (default: 30).

### KnoxIQ Triage

KnoxIQ adds AI-assisted exploitability triage on top of SAST results. It is opt-in per build:

```bash
# Request KnoxIQ triage for this build once the SAST scan completes
appknox upload /path/to/app.apk --knoxiq
```

`cicheck` and `sarif` will then wait for triage (bounded by `--knoxiq-timeout`, shared between
both commands, default: 30 minutes) and fall back to plain SAST results if it doesn't complete
in time:

- `--exploit-likelihood-threshold` (`low`, `medium`, `high`) — fails the build if a triaged
  vulnerability's exploit likelihood is at or above the threshold. Can be combined with
  `--risk-threshold` or `--health-score-threshold`.
- `--include-needs-review` — by default, vulnerabilities KnoxIQ flags as "needs review" are
  excluded from the build decision; this flag includes them.
- `--knoxiq-timeout <minutes>` — how long to wait for KnoxIQ triage before falling back to SAST
  results (1-240, default: 30).

```bash
appknox cicheck 12345 --exploit-likelihood-threshold high
appknox cicheck 12345 --risk-threshold high --include-needs-review
appknox cicheck 12345 --exploit-likelihood-threshold high --knoxiq-timeout 45
```

`sarif` decorates results with AEIS score and exploit likelihood when KnoxIQ triage is available,
and excludes needs-review findings unless `--include-needs-review` is set:

```bash
appknox sarif 12345 --output report.sarif --include-needs-review
```

`--knoxiq-timeout` and `--include-needs-review` can also be set persistently instead of passing
them on every command:

```bash
appknox config set knoxiq-timeout 45
appknox config set include-needs-review true
appknox config get knoxiq-timeout
```

Use `reports knoxiq <file_id>` to generate and download the KnoxIQ PDF report in one step — it
waits for triage to complete (if the build requested it) before downloading, saving to
`./reports/{file_id}/` by default:

```bash
appknox reports knoxiq 12345 --output /path/to/reports/
```

### Download PDF Report

Use `reports create <file_id>` to generate a report and get the report ID, then `reports download pdf <report_id>` to download it.

The `reports download pdf` command:
- Waits (polls every 5s) if the report is still being generated
- Downloads both the encrypted PDF and a `password.txt` file once ready

Files are saved to `./reports/{file_id}/` by default, or to `{output}/{file_id}/` if `--output` is specified.

#### For Linux & macOS platform

```bash
# Download PDF report by report ID
# Saved to: ./reports/{report_id}/report_{report_id}.pdf + report_{report_id}_password.txt
appknox reports download pdf 1

# Download to custom directory
appknox reports download pdf 1 --output /tmp/

# Upload app, create report, then download PDF
fileId=`appknox upload /path/to/app.apk` && appknox cicheck $fileId && reportId=`appknox reports create $fileId` && appknox reports download pdf $reportId --output /path/to/reports/
```

#### For windows platform

```
# Download PDF report by report ID
.\appknox reports download pdf 1

# Download to custom directory
.\appknox reports download pdf 1 --output C:\reports\

# Upload app, create report, then download PDF
$fileId = (.\appknox upload /path/to/app.apk); .\appknox cicheck $fileId; $reportId = (.\appknox reports create $fileId); .\appknox reports download pdf $reportId --output C:\reports\
```

> **Note:** The PDF is password-protected. Use the password from `report_{file_id}_password.txt` to open it. Use `reports create <file_id>` first if you don't have a report ID yet.

---

### Upload App and Download Summary CSV report

#### Linux & macOS platform

```bash
fileId=`appknox upload /path/to/app/binary` && appknox cicheck $fileId ; reportId=`appknox reports create $fileId` && appknox reports download summary-csv $reportId  --output /path/to/report.csv
```

or

#### Run as a bash script
```
./appknox-upload-app-download-summary-csv.sh /path/to/app/binary /path/to/summary-report.csv
```

```
#!/bin/sh
fileId=`./appknox-go upload $1`
./appknox-go cicheck $fileId
reportId=`./appknox-go reports create $fileId`
if ! [ -z "$2" ]; then
  ./appknox-go reports download summary-csv $reportId --output $2
else
  ./appknox-go reports download summary-csv $reportId
fi
```

#### Windows platform

```
$fileId = (appknox upload /path/to/app/binary) && (appknox cicheck $fileId) ; ($reportId = appknox reports create $fileId) && (appknox reports download summary-csv $reportId  --output /path/to/report.csv)

```

or 
#### Run as a powershell script
```
.\appknox-upload-app-download-summary-csv.ps1 /path/to/app/binary /path/to/summary-report.csv
```

```
param (
  [string]$appBinaryPath = "",
  [string]$reportPath = ""
)
$fileId = .\appknox-go upload $appBinaryPath
.\appknox-go cicheck $fileId
$reportId = .\appknox-go reports create $fileId
if ($reportPath) {
  .\appknox-go reports download summary-csv $reportId --output $reportPath
}
else {
  .\appknox-go reports download summary-csv $reportId
}
```
