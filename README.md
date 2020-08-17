[![Github Downloads](https://img.shields.io/github/downloads/dfirence/mitre-assistant/total)]()
[![Github Stars](https://img.shields.io/github/stars/dfirence/mitre-assistant)]()

# mitre-assistant

A custom, more useful, and much cooler MITRE-CTI-CLIENT.

<br/>

![image](https://user-images.githubusercontent.com/11415591/90009693-8a1daa00-dc6c-11ea-87c7-968da8f400e8.png)

<br/>

```bash
# Assumes you have installed the rust tool chain
# and that you have the `cargo` package manager
#
# Preferably use rust stable channel
#
$> cargo install mitre-assistant
```
<br/>

<br/>

<hr>

## W.I.P - Status
- [x] Mitre Enterprise Matrix
- [ ] Mitre Mobile Matrix
- [ ] Mitre Pre-Attack Matrix
- [ ] Mitre Navigator JSON
    - [ ] Legacy Version
    - [ ] Modern Version with Subtechniques
- [x] Linux - 64bit
- [x] MacOS - 64bit
- [x] Windows - 64bit
- [ ] Data Interchange Format
   - [ ] CSV
   - [ ] JSON
- [ ] Exports
   - [ ] CSV
   - [ ] JSON
   - [ ] Rich Web

<hr>

<br/>
<br/>

# Getting Started
You got 3 ways to start using this `bad-boy`:

**1.** You can go to the releases section, download the pre-compiled binary for your os. Note:  I only provide Debian on Linux

**2.** If you already have rust stable toolchain installed, then simply use `cargo install mitre-assistant`

**3.** Or, if you just love building from source, follow the instructions in the `build from source section` below.


<br/>
<br/>

## Releases - Binaries
Head over to the [releases section](https://github.com/dfirence/mitre-assistant/releases/) and download the binary for your OS.  However, note, I am only supporting binaries for **64 bit versions** of:

* MacOS
* Debian
* Windows

<br/>

## Build From Source
If you use a different Linux distro, install the rust toolchain, preferably the stable channel, and follow these steps:

### Step 1 - Clone this repo

```bash
$> git clone https://github.com/dfirence/mitre-assistant.git
```

<br/>

### Step 2 - Navigate into the repo

```bash
$> cd mitre-assistant
```

<br/>

### Step 3 - Build/Compile

```bash
$> cargo build --release
```
<br/>

### Step 4 - Move your fresh binary to a system path

In this step, if you wanna call the executable from anywhere, add it to your system path or executable path - i.e., /usr/bin
```bash
$> sudo mv /target/release/mitre-assistant /usr/bin
```
<br/>

<br/>
<br/>

# How to **Update** with new releases?

```text
Note:   Because this tool is being actively developed,
        it is recommended to always use the `baseline` subcommand
        to ensure the dev changes made to the custom JSON database
        are in effect.
```

Most of the changes being made until I reach **v.1.0** will affect the
JSON file produced by this tool.  This is because I am exploring how to arrange
the data for the outcomes I am pursuing.

So always ensure you run the `baseline` subcommand after you install or download a new version of the tool, for now.

<hr/>
<br/>
<br/>

## Why are you doing this?
I work in the Security industry for a provider, my work hinges a lot on this resource from The Mitre Corporation.  At some point, if you are like me, you will observe the poor and ridiculous amount of time that is needed to create custom datasets from that resource and collaborate across teams to get into serious work.  This helps me not waste time on silly things - i.e., clicking on some website, or asking important questions so I can incorporate the matrix into some form of tactical plans to defend my network, or support new strategies while working with others.

<br/>

## Why not use other existing community tools for this?
I have seen them, used them, and appreciate those that are writing their own. In the end, I am not gonna wait for anyone to do things the way I need them.

<br/>
<br/>

# **Usage**

This is a modular tool. The main concept of using this tool is:

```text

            (1)                      (2)                       (3)
             |                        |                         |
             |                        |                         |
        [ Extract ]-------------[ Transform ]---------------[ Load ]
             |                        |                         |
             |                        |                         |
             |                        |                         |
             v                        v                         v
       Download A Matrix         Baseline The Matrix        Search - Ask your question
```
<br/>
<br/>

## **Help Menu**
Building from the above concept, let's get into using this bad-boy.

<br/>

```bash
cdiaz@[mitre-assistant]
 >> mitre-assistant -h



mitre-assistant v.0.0.10
carlos diaz | @dfirence

Mitre Attack Assistant

        A more useful utility for the ATT&CK Matrix

USAGE:
    mitre-assistant [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    baseline    Parse a Matrix into comprehensive insights
    download    Download a Matrix From The Mitre CTI Repo
    help        Prints this message or the help of the given subcommand(s)
    search      Search The Baseline
```
<br/>
<br/>

# *Download*
Use the `download` subcommand to get started, you can specific which matrix to download by using any of the keywords: `enterprise` or `mobile` or `pre-attack`

<br/>

```bash
# Assumes you want to download the `enterprise` matrix
#
$> mitre-assistant download -m enterprise


# Output
===========================================================================================

Downlading Matrix : enterprise
Downloading From  : https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

===========================================================================================
        |__(+) New File To Be Created: /Users/alice/.mitre-assistant/matrixes/enterprise.json
```
<br/>
<br/>

# *Baseline*
Use the `baseline` subcommand after you download your matrix to create the custom database that is required before you conduct your searches.

You baseline a matrix with any of the keywords:  `enterprise` or `mobile` or `pre-attack`

<br/>

```bash
$> mitre-assistant baseline -m enterprise


#Output
/Users/alice/.mitre-assistant/matrixes/enterprise.json
  |__(+) New File To Be Created: /Users/alice/.mitre-assistant/baselines/baseline-enterprise.json
```
<br/>
<br/>

# *Search*
Now you are ready to search your matrix.

You have to tell the `search subcommand` which matrix it is going to work with by using:

* the `-m` parameter followed by the name of the matrix 
* the `-t` parameter to provide your search term.

<br/>
<br/>

## *Search Terms*

|TERM|MATRIX|PURPOSE|
|----|------|-------|
|`datasources`|*enterprise*|Returns all datasources from the matrix|
|`deprecated`|*enterprise*|Returns all the deprecated techniques from the matrix|
|`platforms`|*enterprise*|Returns all the platforms (operating systems) from the matrix|
|`nodatasources`|*enterprise*|Returns all techniques or subtechniques **without** datasources|
|`nosub`|*enterprise*|Returns all the active techniques which do not have/use subtechniques|
|`revoked`|*enterprise*|Returns all of the technique id & name references revoked by Mitre|
|`stats`|*enterprise*|Returns an overview of `uniq` counts and `total` counts of key data elements|
|`subtechniques`|*enterprise*|Returns all subtechniques from the matrix|
|`techniques`|*enterprise*|Returns all techniques from the matrix|
|`tactics`|*enterprise*|Returns all tactics from the matrix|
|||
|||
|`initial-access`|*enterprise*|Returns all techniques in the **Initial Access** Tactic|
|`execution`|*enterprise*|Returns all techniques in the **Execution** Tactic|
|`persistence`|*enterprise*|Returns all techniques in the **Persistence** Tactic|
|`privilege-escalation`|*enterprise*|Returns all techniques in the **Privilege Escalation** Tactic|
|`defense-evasion`|*enterprise*|Returns all techniques in the **Defense Evasion** Tactic|
|`credential-access`|*enterprise*|Returns all techniques in the **Credential Access** Tactic|
|`discovery`|*enterprise*|Returns all techniques in the **Discovery** Tactic|
|`lateral-movement`|*enterprise*|Returns all tecniques in **Lateral Movement** Tactic|
|`collection`|*enterprise*|Returns all techniques in the **Collection** Tactic|
|`command-and-control`|*enterprise*|Returns all techniques in the **Command And Control** Tactic|
|`exfiltration`|*enterprise*|Returns all techniques in the **Exfiltration** Tactic|
|`impact`|*enterprise*|Returns all techniques in the **Impact** Tactic|
|||
|||
|`aws`|*enterprise*|Returns all techniques in the **AWS** Platform|
|`azure`|*enterprise*|Returns all techniques in the **AZURE** Platform|
|`azure-ad`|*enterprise*|Returns all techniques in the **AZURE-AD** Platform|
|`gcp`|*enterprise*|Returns all techniques in the **GCP** Platform|
|`linux`|*enterprise*|Returns all techniques in the **LINUX** Platform|
|`macos`|*enterprise*|Returns all techniques in the **MACOS** Platform|
|`office-365`|*enterprise*|Returns all techniques in the **OFFICE-365** Platform|
|`saas`|*enterprise*|Returns all techniques in the **SAAS** Platform|
|`windows`|*enterprise*|Returns all techniques in the **WINDOWS** Platform|
|||
|||
|`xref:datasources:platforms`|*enterprise*|Returns a 2d matrix of active techniques by datasource mapped to platform|
|`xref:datasources:tactics`|*enterprise*|Returns a 2d matrix of active techniques by datasource mapped to tactics|

<br/>
<br/>
<br/>

## *Searching The Enterprise Matrix For An Overview Stats Summary*
You use the keyword `stats` in your search term, like this

```bash
# Assumed you want the summary of items in the matrix
#
$> mitre-assistant search -m enterprise -t "stats"
```
<br/>
<br/>

<div align="center"><h2>Unique & Total Counts</h2></div>

<hr/>
<div align="center">
    <img src="https://user-images.githubusercontent.com/11415591/89737350-33328d80-da3e-11ea-9f76-311251cfc851.png"></img>
</div>
<hr/>
<br/>
<br/>

<div align="center"><h2>By Platform</h2></div>

| TECHNIQUES | SUBTECHNIQUES|
|------------|--------------|
|![image](https://user-images.githubusercontent.com/11415591/89737360-47768a80-da3e-11ea-95da-81f68342624d.png)|![image](https://user-images.githubusercontent.com/11415591/89737366-54937980-da3e-11ea-981d-06518ef06e43.png)|

<hr/>
<br/>
<br/>

<div align="center"><h2>By Tactic/KillChain</h2></div>

| TACTICS - TECHNIQUES | TACTICS - SUBTECHNIQUES|
|------------|--------------|
|![image](https://user-images.githubusercontent.com/11415591/89737321-0bdbc080-da3e-11ea-9030-849fbd9420b2.png)|![image](https://user-images.githubusercontent.com/11415591/89737328-18f8af80-da3e-11ea-866f-2a09231aeee4.png)|


<hr/>
<br/>
<br/>


<hr/>
<br/>
<br/>

## *Searching The Enterprise Matrix For Techniques By Name*

By default, searching by the **name** of a technique is offered with a **partial match**.  Whereas, searching by technique id is a **full match**.

This means, you can search for techniques by name entering strings that may be incomplete, and the tool finds all references to your input.

Let's take a look at this example, where we search for any technique that has the word **boot**

```bash
# Assumes you want to search for techniques
# that have the word `boot`
#
$> mitre-assistant search -m enterprise -t "boot"
```
<br/>

The command above results in the image below, notice how the word `boot` matches across different techniques.

<br/>

![image](https://user-images.githubusercontent.com/11415591/90316166-50f46c80-deee-11ea-8254-4630516086f2.png)

<br/>
<br/>

## *Searching The Enterprise Matrix For A Single Technique By ID*


<br/>

```bash
# Assumes you want to search/query the enterprise matrix
# All terms must be enclosed by double-quotes
#
$> mitre-assistant search -m enterprise -t "t1021"
```
<br/>

![image](https://user-images.githubusercontent.com/11415591/89109722-cf8edb80-d411-11ea-82b5-3a4dde2d90b1.png)

<br/>

## *Searching The Enterprise Matrix For Many Techniques By ID*
Cool, now you just have to add a comma `,` in your term and launch it again, dead-simple!

<br/>

```bash
# Assumes you want to search for techniques:  T1021 & T1048
#
$> mitre-assistant search -m enterprise -t "t1021,t1048"

```

<br/>

![image](https://user-images.githubusercontent.com/11415591/89109703-ae2def80-d411-11ea-9268-ab7f42527386.png)

<br/>

## *Searching The Enterprise Matrix & Displaying The Subtechniques*
Another cool thing here is display the `subtechniques` for your query by using:

* the `-s` flag after your query

<br/>

```bash
# Assumes you want to see the Subtechniques for T1021
$> mitre-assistant search -m enterprise -t "t1021" -s
```
<br/>

![image](https://user-images.githubusercontent.com/11415591/89109790-69568880-d412-11ea-9869-325a35d7de13.png)

<br/>

## *Searching The Enterprise Matrix By Tactic**
You can ask the tool to give you all the techniques for a specific `Mitre Tactic`. You need to follow the convention used in the tool to get the right tactic.

This section describes how you can quickly ramp up on using tactic queries.

### **Step 1:  List of the Tactics in the Matrix**

* the `-t` parameter with the term `tactics`

```bash
# Assumes you want to know the Tactics
#
$> mitre-assistant search -m enterprise -t "tactics"

# Output 
                +-------+----------------------+
                | INDEX | TACTICS              |
                +-------+----------------------+
                | 1     | collection           |
                +-------+----------------------+
                | 2     | command-and-control  |
                +-------+----------------------+
                | 3     | credential-access    |
                +-------+----------------------+
                | 4     | defense-evasion      |
                +-------+----------------------+
                | 5     | discovery            |
                +-------+----------------------+
                | 6     | execution            |
                +-------+----------------------+
                | 7     | exfiltration         |
                +-------+----------------------+
                | 8     | impact               |
                +-------+----------------------+
                | 9     | initial-access       |
                +-------+----------------------+
                | 10    | lateral-movement     |
                +-------+----------------------+
                | 11    | persistence          |
                +-------+----------------------+
                | 12    | privilege-escalation |
                +-------+----------------------+
```
<br/>
<br/>

### **Step 2: Search By Tactic**

Now you can use any of the tactics above in your search query, like this:

* the `-t` parameter with the term `{{ tactic_name }}`
  
<br/>

```bash
# Assumes you want to search by the `initial-access` tactic
#
$> mitre-assistant search -m enterprse -t "initial-access"

```
<br/>

![image](https://user-images.githubusercontent.com/11415591/90316089-1094ee80-deee-11ea-8c38-f75ed7a3b6e5.png)

<br/>
<br/>

## *Searching For The Revoked Techniques*
Revoked techniques seem to be those that are discontinued and re-arranged now into subtechniques.  You can search for the ones `revoked` in the matrix by using a keyword in your search term:

* the `-t` parameter with the term `revoked`

<br/>

```bash
# Assumes you want to see the Revoked Techniques
#
$> mitre-assistant search -m enterprise -t "revoked"

# Output

                    +-------+---------+-------+-------------------------------------------------------+
                    | INDEX | STATUS  | TID   | TECHNIQUE                                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 1     | Revoked | T1002 | Data Compressed                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 2     | Revoked | T1004 | Winlogon Helper DLL                                   |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 3     | Revoked | T1009 | Binary Padding                                        |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 4     | Revoked | T1013 | Port Monitors                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 5     | Revoked | T1015 | Accessibility Features                                |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 6     | Revoked | T1017 | Application Deployment Software                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 7     | Revoked | T1019 | System Firmware                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 8     | Revoked | T1022 | Data Encrypted                                        |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 9     | Revoked | T1023 | Shortcut Modification                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 10    | Revoked | T1024 | Custom Cryptographic Protocol                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 11    | Revoked | T1028 | Windows Remote Management                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 12    | Revoked | T1031 | Modify Existing Service                               |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 13    | Revoked | T1032 | Standard Cryptographic Protocol                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 14    | Revoked | T1035 | Service Execution                                     |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 15    | Revoked | T1038 | DLL Search Order Hijacking                            |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 16    | Revoked | T1042 | Change Default File Association                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 17    | Revoked | T1044 | File System Permissions Weakness                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 18    | Revoked | T1045 | Software Packing                                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 19    | Revoked | T1050 | New Service                                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 20    | Revoked | T1054 | Indicator Blocking                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 21    | Revoked | T1058 | Service Registry Permissions Weakness                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 22    | Revoked | T1060 | Registry Run Keys / Startup Folder                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 23    | Revoked | T1063 | Security Software Discovery                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 24    | Revoked | T1065 | Uncommonly Used Port                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 25    | Revoked | T1066 | Indicator Removal from Tools                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 26    | Revoked | T1067 | Bootkit                                               |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 27    | Revoked | T1073 | DLL Side-Loading                                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 28    | Revoked | T1075 | Pass the Hash                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 29    | Revoked | T1076 | Remote Desktop Protocol                               |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 30    | Revoked | T1077 | Windows Admin Shares                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 31    | Revoked | T1079 | Multilayer Encryption                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 32    | Revoked | T1081 | Credentials in Files                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 33    | Revoked | T1084 | Windows Management Instrumentation Event Subscription |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 34    | Revoked | T1085 | Rundll32                                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 35    | Revoked | T1086 | PowerShell                                            |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 36    | Revoked | T1088 | Bypass User Account Control                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 37    | Revoked | T1089 | Disabling Security Tools                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 38    | Revoked | T1093 | Process Hollowing                                     |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 39    | Revoked | T1094 | Custom Command and Control Protocol                   |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 40    | Revoked | T1096 | NTFS File Attributes                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 41    | Revoked | T1097 | Pass the Ticket                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 42    | Revoked | T1099 | Timestomp                                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 43    | Revoked | T1100 | Web Shell                                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 44    | Revoked | T1101 | Security Support Provider                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 45    | Revoked | T1103 | AppInit DLLs                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 46    | Revoked | T1107 | File Deletion                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 47    | Revoked | T1109 | Component Firmware                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 48    | Revoked | T1116 | Code Signing                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 49    | Revoked | T1117 | Regsvr32                                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 50    | Revoked | T1118 | InstallUtil                                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 51    | Revoked | T1121 | Regsvcs/Regasm                                        |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 52    | Revoked | T1122 | Component Object Model Hijacking                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 53    | Revoked | T1126 | Network Share Connection Removal                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 54    | Revoked | T1128 | Netsh Helper DLL                                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 55    | Revoked | T1130 | Install Root Certificate                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 56    | Revoked | T1131 | Authentication Package                                |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 57    | Revoked | T1138 | Application Shimming                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 58    | Revoked | T1139 | Bash History                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 59    | Revoked | T1141 | Input Prompt                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 60    | Revoked | T1142 | Keychain                                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 61    | Revoked | T1143 | Hidden Window                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 62    | Revoked | T1144 | Gatekeeper Bypass                                     |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 63    | Revoked | T1145 | Private Keys                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 64    | Revoked | T1146 | Clear Command History                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 65    | Revoked | T1147 | Hidden Users                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 66    | Revoked | T1148 | HISTCONTROL                                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 67    | Revoked | T1150 | Plist Modification                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 68    | Revoked | T1151 | Space after Filename                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 69    | Revoked | T1152 | Launchctl                                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 70    | Revoked | T1154 | Trap                                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 71    | Revoked | T1155 | AppleScript                                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 72    | Revoked | T1156 | .bash_profile and .bashrc                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 73    | Revoked | T1157 | Dylib Hijacking                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 74    | Revoked | T1158 | Hidden Files and Directories                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 75    | Revoked | T1159 | Launch Agent                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 76    | Revoked | T1160 | Launch Daemon                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 77    | Revoked | T1161 | LC_LOAD_DYLIB Addition                                |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 78    | Revoked | T1162 | Login Item                                            |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 79    | Revoked | T1163 | Rc.common                                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 80    | Revoked | T1164 | Re-opened Applications                                |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 81    | Revoked | T1165 | Startup Items                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 82    | Revoked | T1166 | Setuid and Setgid                                     |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 83    | Revoked | T1167 | Securityd Memory                                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 84    | Revoked | T1168 | Local Job Scheduling                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 85    | Revoked | T1169 | Sudo                                                  |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 86    | Revoked | T1170 | Mshta                                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 87    | Revoked | T1171 | LLMNR/NBT-NS Poisoning and Relay                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 88    | Revoked | T1172 | Domain Fronting                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 89    | Revoked | T1173 | Dynamic Data Exchange                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 90    | Revoked | T1174 | Password Filter DLL                                   |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 91    | Revoked | T1177 | LSASS Driver                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 92    | Revoked | T1178 | SID-History Injection                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 93    | Revoked | T1179 | Hooking                                               |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 94    | Revoked | T1180 | Screensaver                                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 95    | Revoked | T1181 | Extra Window Memory Injection                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 96    | Revoked | T1182 | AppCert DLLs                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 97    | Revoked | T1183 | Image File Execution Options Injection                |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 98    | Revoked | T1184 | SSH Hijacking                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 99    | Revoked | T1186 | Process Doppelgänging                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 100   | Revoked | T1188 | Multi-hop Proxy                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 101   | Revoked | T1191 | CMSTP                                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 102   | Revoked | T1192 | Spearphishing Link                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 103   | Revoked | T1193 | Spearphishing Attachment                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 104   | Revoked | T1194 | Spearphishing via Service                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 105   | Revoked | T1196 | Control Panel Items                                   |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 106   | Revoked | T1198 | SIP and Trust Provider Hijacking                      |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 107   | Revoked | T1206 | Sudo Caching                                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 108   | Revoked | T1208 | Kerberoasting                                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 109   | Revoked | T1209 | Time Providers                                        |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 110   | Revoked | T1214 | Credentials in Registry                               |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 111   | Revoked | T1215 | Kernel Modules and Extensions                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 112   | Revoked | T1223 | Compiled HTML File                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 113   | Revoked | T1483 | Domain Generation Algorithms                          |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 114   | Revoked | T1487 | Disk Structure Wipe                                   |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 115   | Revoked | T1488 | Disk Content Wipe                                     |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 116   | Revoked | T1492 | Stored Data Manipulation                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 117   | Revoked | T1493 | Transmitted Data Manipulation                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 118   | Revoked | T1494 | Runtime Data Manipulation                             |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 119   | Revoked | T1500 | Compile After Delivery                                |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 120   | Revoked | T1501 | Systemd Service                                       |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 121   | Revoked | T1502 | Parent PID Spoofing                                   |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 122   | Revoked | T1503 | Credentials from Web Browsers                         |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 123   | Revoked | T1504 | PowerShell Profile                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 124   | Revoked | T1506 | Web Session Cookie                                    |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 125   | Revoked | T1514 | Elevated Execution with Prompt                        |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 126   | Revoked | T1519 | Emond                                                 |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 127   | Revoked | T1522 | Cloud Instance Metadata API                           |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 128   | Revoked | T1527 | Application Access Token                              |
                    +-------+---------+-------+-------------------------------------------------------+
                    | 129   | Revoked | T1536 | Revert Cloud Instance                                 |
                    +-------+---------+-------+-------------------------------------------------------+
```
<br/>

<br/>
<br/>

## *Searching For The Deprecated Techniques*
Deprecated techniques seem to be those that are no longer valid and used in a mtrix.  You can search for the ones `deprecated` in the matrix by using a keyword in your search term:

* the `-t` parameter with the term `deprecated`

<br/>

```bash
# Assumes you want to see the Deprecated Techniques
#
$> mitre-assistant search -m enterprise -t "deprecated"

# Output

                    +-------+------------+-------+--------------------------------------------+
                    | INDEX | STATUS     | TID   | TECHNIQUE                                  |
                    +-------+------------+-------+--------------------------------------------+
                    | 1     | Deprecated | T1026 | Multiband Communication                    |
                    +-------+------------+-------+--------------------------------------------+
                    | 2     | Deprecated | T1034 | Path Interception                          |
                    +-------+------------+-------+--------------------------------------------+
                    | 3     | Deprecated | T1043 | Commonly Used Port                         |
                    +-------+------------+-------+--------------------------------------------+
                    | 4     | Deprecated | T1051 | Shared Webroot                             |
                    +-------+------------+-------+--------------------------------------------+
                    | 5     | Deprecated | T1061 | Graphical User Interface                   |
                    +-------+------------+-------+--------------------------------------------+
                    | 6     | Deprecated | T1062 | Hypervisor                                 |
                    +-------+------------+-------+--------------------------------------------+
                    | 7     | Deprecated | T1064 | Scripting                                  |
                    +-------+------------+-------+--------------------------------------------+
                    | 8     | Deprecated | T1108 | Redundant Access                           |
                    +-------+------------+-------+--------------------------------------------+
                    | 9     | Deprecated | T1149 | LC_MAIN Hijacking                          |
                    +-------+------------+-------+--------------------------------------------+
                    | 10    | Deprecated | T1153 | Source                                     |
                    +-------+------------+-------+--------------------------------------------+
                    | 11    | Deprecated | T1175 | Component Object Model and Distributed COM |
                    +-------+------------+-------+--------------------------------------------+
```
<br/>
<br/>
<br/>


## *Searching For The Platforms*
Platforms are the relevant operating systems where a technique is exercised or abused by an adversary. To get the platforms in the enterprise matrix use the keyword `platforms`.

* the `-t` parameter with the term `platforms`

<br/>

```bash
# Assumes you want to see All Platforms
# for the enterprise matrix
#
$> mitre-assistant search -m enterprise -t "platforms"

# Output

                    +-------+------------+
                    | INDEX | PLATFORMS  |
                    +-------+------------+
                    | 1     | macos      |
                    +-------+------------+
                    | 2     | azure      |
                    +-------+------------+
                    | 3     | aws        |
                    +-------+------------+
                    | 4     | office-365 |
                    +-------+------------+
                    | 5     | azure-ad   |
                    +-------+------------+
                    | 6     | windows    |
                    +-------+------------+
                    | 7     | saas       |
                    +-------+------------+
                    | 8     | linux      |
                    +-------+------------+
                    | 9     | gcp        |
                    +-------+------------+
```

<br/>
<br/>

## *Searching The Enterprise Matrix For All Techniques By Platform*

You can ask the tool to give you all the **active techniques** based on a specific platform, like this.

* the `-t` parameter with the term `{{ platform_name }}`

<br/>

```bash
# Assumes you want to see All Techniques By The Linux Platform
#
$> mitre-assistant search -m enterprise -t "linux"
```

<br/>

The query above produces the image below, notice how the `PLATFORMS` column denotes the platform you wanted.

<br/>
<div align="center">
    <img src="https://user-images.githubusercontent.com/11415591/90335096-3084ea80-dfa0-11ea-8a5c-6e16b4c34561.png"></img>
</div>
<br/>
<br/>

## *Searching For The Datasources*

```text
Protip:

1. Do not follow Mitre blindly, you need to curate their content
and organize it.

Example:

1. DLL Monitoring & Loaded DLLs

Mitre currently has these two datasources, what does this mean?

To me in the security Space, there's only one source, not two.
```
<br/>

Datasources are a non-concrete description by Mitre that seems to suggest the context of evidence needed to be successful at pursuing visibility or detection capabilities for the given technique. This query gets you the datasources as provided by Mitre in their CTI github

* the `-t` parameter with the term `datasources`

<br/>

```bash
# Assumes you want to see All Datasources
# for the enterprise matrix
#
$> mitre-assistant search -m enterprise -t "datasources"

# Output

                +-------+------------------------------------+
                | INDEX | DATASOURCE                         |
                +-------+------------------------------------+
                | 1     | access-tokens                      |
                +-------+------------------------------------+
                | 2     | anti-virus                         |
                +-------+------------------------------------+
                | 3     | api-monitoring                     |
                +-------+------------------------------------+
                | 4     | application-logs                   |
                +-------+------------------------------------+
                | 5     | asset-management                   |
                +-------+------------------------------------+
                | 6     | authentication-logs                |
                +-------+------------------------------------+
                | 7     | aws-cloudtrail-logs                |
                +-------+------------------------------------+
                | 8     | azure-activity-logs                |
                +-------+------------------------------------+
                | 9     | binary-file-metadata               |
                +-------+------------------------------------+
                | 10    | bios                               |
                +-------+------------------------------------+
                | 11    | browser-extensions                 |
                +-------+------------------------------------+
                | 12    | component-firmware                 |
                +-------+------------------------------------+
                | 13    | data-loss-prevention               |
                +-------+------------------------------------+
                | 14    | detonation-chamber                 |
                +-------+------------------------------------+
                | 15    | digital-certificate-logs           |
                +-------+------------------------------------+
                | 16    | disk-forensics                     |
                +-------+------------------------------------+
                | 17    | dll-monitoring                     |
                +-------+------------------------------------+
                | 18    | dns-records                        |
                +-------+------------------------------------+
                | 19    | efi                                |
                +-------+------------------------------------+
                | 20    | email-gateway                      |
                +-------+------------------------------------+
                | 21    | environment-variable               |
                +-------+------------------------------------+
                | 22    | file-monitoring                    |
                +-------+------------------------------------+
                | 23    | gcp-audit-logs                     |
                +-------+------------------------------------+
                | 24    | host-network-interface             |
                +-------+------------------------------------+
                | 25    | kernel-drivers                     |
                +-------+------------------------------------+
                | 26    | loaded-dlls                        |
                +-------+------------------------------------+
                | 27    | mail-server                        |
                +-------+------------------------------------+
                | 28    | malware-reverse-engineering        |
                +-------+------------------------------------+
                | 29    | mbr                                |
                +-------+------------------------------------+
                | 30    | named-pipes                        |
                +-------+------------------------------------+
                | 31    | netflow/enclave-netflow            |
                +-------+------------------------------------+
                | 32    | network-device-logs                |
                +-------+------------------------------------+
                | 33    | network-intrusion-detection-system |
                +-------+------------------------------------+
                | 34    | network-protocol-analysis          |
                +-------+------------------------------------+
                | 35    | oauth-audit-logs                   |
                +-------+------------------------------------+
                | 36    | office-365-account-logs            |
                +-------+------------------------------------+
                | 37    | office-365-audit-logs              |
                +-------+------------------------------------+
                | 38    | office-365-trace-logs              |
                +-------+------------------------------------+
                | 39    | packet-capture                     |
                +-------+------------------------------------+
                | 40    | powershell-logs                    |
                +-------+------------------------------------+
                | 41    | process-command-line-parameter    |
                +-------+------------------------------------+
                | 42    | process-monitoring                 |
                +-------+------------------------------------+
                | 43    | process-use-of-network             |
                +-------+------------------------------------+
                | 44    | sensor-health-and-status           |
                +-------+------------------------------------+
                | 45    | services                           |
                +-------+------------------------------------+
                | 46    | ssl/tls-inspection                 |
                +-------+------------------------------------+
                | 47    | stackdriver-logs                   |
                +-------+------------------------------------+
                | 48    | system-calls                       |
                +-------+------------------------------------+
                | 49    | third-party-application-logs       |
                +-------+------------------------------------+
                | 50    | user-interface                     |
                +-------+------------------------------------+
                | 51    | vbr                                |
                +-------+------------------------------------+
                | 52    | web-application-firewall-logs      |
                +-------+------------------------------------+
                | 53    | web-logs                           |
                +-------+------------------------------------+
                | 54    | web-proxy                          |
                +-------+------------------------------------+
                | 55    | windows-error-reporting            |
                +-------+------------------------------------+
                | 56    | windows-event-logs                 |
                +-------+------------------------------------+
                | 57    | windows-registry                   |
                +-------+------------------------------------+
                | 58    | wmi-objects                        |
                +-------+------------------------------------+
```

<br/>
<br/>

## *Searching Datasources With Cross References: **Experimental***
At this moment, v.0.0.10 and above allow for experimental cross-references of datasources and `platforms`, as well as, `tactics`.

This experiment is to understand, based on the suggested datasources by Mitre, where do they fit according to the platforms or tactics.

**SPECIAL NOTE**:  The queries for cross-references **only compute** counts against the `Active Techniques` total. No Subtechniques are taken into account, yet.

<br/>

To launch a cross-reference query you use a prefix in your term - `xref:`, let's look at an example

* the `-t` parameter with the term `xref:datasources:{{ reference_type }}`
  
<br/>

```bash
# Assumes you want to cross-reference datasources to platforms
#
$> mitre-assistant search -m enterprise -t "xref:datasources:platforms"
```

<br/>

Notice the above command uses a colon "`:`" character to tell the search engne this is a cross-reference query.
The above command results in the image below.

<br/>

![image](https://user-images.githubusercontent.com/11415591/90342001-91c5b180-dfd2-11ea-994f-ba259b06e947.png)

<br/>
<br/>

In contrast, let's launch a cross-reference query against the tactics, like this:

```bash
# Assumes you want to cross-reference datasources to tactics
#
$> mitre-assistant search -m enterprise -t "xref:datasources:tactics"
```

<br/>

And that now produces this image below.

<br/>

![image](https://user-images.githubusercontent.com/11415591/90341975-53c88d80-dfd2-11ea-9106-2db9843e7b8a.png)

<br/>
<br/>

## *Searching For Edge Cases:  Techniques Without a Subtechniques*
Some techniques, do not have subtechniques assigned, or as I like to thunk of it, have not been fully updated by Mitre.

Use the keyword `nosub` to obtain a list of active techniques that may not have an assigned subtechnique by Mitre.

* the `-t` parameter with the term `nosub`

<br/>

```bash
# Assumes you want to see the Techniques that do not have Subtechniques
# for the enterprise matrix
#
$> mitre-assistant search -m enterprise -t "nosub"
```

<br/>
<br/>

![image](https://user-images.githubusercontent.com/11415591/90009417-0663bd80-dc6c-11ea-87d0-ad91d71ecc51.png)

<br/>

## *Searching For Edge Cases:  Techniques Without a Datasource*
This is the edge-case that drove to create this tool for myself.  I found someone's tool incorrectly parsed the matrix and I needed to report to my management the plan of action based on data sources.  This is very important for practitioners who leverage the matrix for real world tactical operations.

Reference this example:  [NO_DATA_SOURCE_SAMPLE](https://user-images.githubusercontent.com/11415591/88487153-a58c7380-cf50-11ea-8547-e03a6b7a9185.png)

Use the keyword `nodatasources` to obtain a list of active techniques that may not have an assigned datasource by Mitre.

* the `-t` parameter with the term `nodatasources`

<br/>

```bash
# Assumes you want to see the Techniques that do not have Datasources
# for the enterprise matrix
#
$> mitre-assistant search -m enterprise -t "nodatasources"
```

<br/>
<br/>

![image](https://user-images.githubusercontent.com/11415591/89842172-dd93d900-db42-11ea-81c9-89d5a5c85961.png)

<br/>



# **Statistical Stuff**
As I mentioned, my work with this matrix is at the provider level, I have to devise coverage plans, or brainstorming workshops with my fellow blue-teamers to understand what an emulation plan means in terms of effort, engineering for new content and consequently sizing our systems to increase our visibility and detection needs.

These experiments were very useful to me a couple of years ago as I started learning about the Mitre ATT&CK matrixes.

<br/>

## TODO: Awesome Stuff here


<br/>
<br/>
<br/>

# References
|SOURCE|URL|
|------|---|
|Mitre CTI Github|[LINK](https://github.com/mitre/cti/blob/master/USAGE.md#working-with-deprecated-and-revoked-objects)|

<br/>
<br/>

# Kudos - RUSTACEANS
Many super kudos, to the amazing RUST Community, for their warm embrace of everyone that wants the journey.  Seemingly, to all of the super creators of loved tools from python being ported into rust.

## TODO - Thank Crates Contributions