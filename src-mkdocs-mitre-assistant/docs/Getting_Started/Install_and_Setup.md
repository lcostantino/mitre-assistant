To get started, you have several options.

**1.** You can use pre-built binaries for your operating system. Go Here: <a href="https://github.com/dfirence/mitre-assistant/releases" target="_blank" norelopener><strong>releases section</strong></a> 

**2.** You can install from crates.io.  Go Here: <a href="https://crates.io/crates/mitre-assistant" target="_blank" norelopener><strong>crates.io mitre-assistant</strong></a> 

**3.** You can build from source. Follow the instructions below for `Building From Source`

<br/>

## **Building From Source**

You will need to have installed the rust stable toolchain, then clone the github repository, then build, like this:

!!! tip "Mitre-Assistant Building From Source"

    === "Clone Repo"

        ```bash
        git clone https://github.com/dfirence/mitre-assistant.git
        ```

    === "Build Repo"

        ```bash
        cd mitre-assistant
        ```

        Then Build

        ```bash
        cargo build --release
        ```
    
    === "Copy Your Binary"

        ```bash
        cp -v ./target/release/mitre-assistant ~/.cargo/bin
        ```

        Or if you want to move it to a global env for all users

        ```bash
        sudo cp -v ./target/release/mitre-assistant /usr/bin/mitre-assistant
        ```
    
<br/>
<hr/>

## **What is a Mitre-Assistant Baseline?**

It is a custom JSON file I created for the Mitre-Assistant to use in its representation of data you will query for. Think of it as the backend database used by the program.
<br/>

### Setup Baselines
The Mitre-Assistant is buildt with an `ETL` concept. The ETL stands for, **extract**, **transform**, **load**. 

The primary datasource is provided by The Mitre Corporation's <a href="https://github.com/mitre/cti" target="_blank" norelopener>STIX CTI Repo</a>, and from here, you will be able to access each specific matrix type.

The Mitre-Assistant leverages at this time, the <a href="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" target="_blank" norelopener>enterprise matrix</a>, which is provided by the json file in the matrix.

Finally the Mitre-Assistant allows you to download that file, and upon downloading, it begins to extract/transform/load the data in a custom JSON format I created so it is easier to work with the original STIX Format.

Follow these steps to set up your baselines.

=== "Step 1 - Get The Enterprise Matrix"

    ```bash
    mitre-assistant download -m enterprise
    ```
    
=== "Step 2 - Create The Baseline"

    ```bash
    mitre-assistant baseline -m enterprise
    ```

=== "Step 3 - Validate The Baseline"
    
    ```bash
    ls -la ~/.mitre-assistant/baselines
    ```

<br/>

### **Setup a Legacy Baseline**

The legacy baseline, is the previous version of the Mitre ATT&CK Matrix - V6.  This is the version that did not have **subtechniques** being introduced into the matrix.  You can work with that legacy mode by using the commandline options below.

=== "Step 1 - Get The Legacy Enterprise Matrix"

    **Notice** the usage of **enterprise-legacy** in these steps :)

    ```bash
    mitre-assistant download -m enterprise-legacy
    ```
    
=== "Step 2 - Create The Baseline"

    ```bash
    mitre-assistant baseline -m enterprise-legacy
    ```

=== "Step 3 - Validate The Baseline"
    
    ```bash
    ls -la ~/.mitre-assistant/baselines
    ```

<br/>

## Updating Baselines
As you download the baselines into your machine, you are essentially working with a snapshot of the CTI Repo for the day you downloaded it.

If, you want to continuously update the local baselines, you **must** do this yourself.  An easy way to achieve this, is by setting up a Windows Task or Linux Cron Job that runs the commands above for you on a continuous basis.

<br/>
<hr/>

## Validating The Install

To ensure everything is working after the steps above, you can now conduct a query, test the export to csv, or export to json, like this.

=== "Simple Query"
    
    ```bash
    mitre-assistant search -m enterprise -t "t1210"
    ```

    Output

    ![image](https://user-images.githubusercontent.com/11415591/95684370-36253800-0bbf-11eb-9800-773de605ee80.png)

    
=== "Export to JSON"

    ```bash
    mitre-assistant search -m enterprise -t "t1210" -e json
    ```

    Output

    ```json
    [
        {
            "id": "attack-pattern--9db0cf3a-a3c9-4012-8268-123b9db6fd82",
            "platform": "linux|windows|macos",
            "tid": "T1210",
            "technique": "Exploitation of Remote Services",
            "tactic": "lateral-movement",
            "datasources": "file-monitoring|process-monitoring|windows-error-reporting",
            "has_subtechniques": false,
            "is_deprecated": false,
            "is_revoked": false,
            "subtechniques": [],
            "count_subtechniques": 0,
            "correlation_adversary": "none",
            "correlation_malware": "none",
            "correlation_tool": "none"
        }
    ]
    ```

=== "Export to CSV"

    ```bash
    mitre-assistant search -m enterprise -t "t1210" -e csv
    ```

    Output

    ```csv
    INDEX,STATUS,PLATFORMS,TACTIC,TID,TECHNIQUE,SUBTECHNIQUES,DATA SOURCES
    1,Active,linux|windows|macos,lateral-movement,T1210,Exploitation of Remote Services,n_a,file-monitoring|process-monitoring|windows-error-reporting
    ```