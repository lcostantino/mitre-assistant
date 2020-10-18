Before we dive into the practical tips, **==it is critical to understand==** the Mitre ATT&CK framework should not be considered the single source of truth, but rather, a source of excellent knowledge that is progressively making strides to bring security practitioners a common-language and possibly, common-sense.

I will be outlining the reasons why I believe this is the case.

## Reasons

### Empirical Context From External Contributions
The ATT&CK Matrix as published, derives its structure from many contributions of external opinions, analysis, and observations of various indviduals and organizations that provide security services, not excluding the independent opinions of qualified individuals.  However, the data is partially incomplete.

<br/>

!!! info "Observation: Adversary G0015| a.k.a Taidoor"
    <br/>
    Run this query in the Mitre-Assistant.

    ```bash
    mitre-assistant search -m enterprise -t "taidoor" 
    ```

    **You will not find information of techniques** on this adversary although it is published in the matrix.

    Now, Reference these links from reputable sources on `taidoor`

    <a href="https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a" target="_blank" norelopener>US_CERT_TAIDOOR</a>

    <a href="https://malpedia.caad.fkie.fraunhofer.de/actor/taidoor"
       target="_blank" norelopener>MALPEDIA_TAIDOOR_ADVERSARY</a>

<br/>

The above example demonstrates the incompleteness of the information offered in the Matrix, therefore, **==this is not a criticism==**, rather it is a factual observation for practitioners or security leaders to have present when working with the Matrix to pursue security outcomes.  Therefore, you **==should not follow==** the matrix blindly, instead you have to encourage your team(s) to scavenge or produce complementary information that can afford you the insights you are in need of when working with the approach suggested by the Mitre Corporation - i.e., emulate behaviors, record them, and formulate your own tactical plans based on the exhibited techniques of the adversary of malware you are investigating.

<br/>

### Incomplete Datasource Context

Working with suggested datasources from the Matrix has ***signficant value***, **==however==**, it is important to note that as of the time of this writing the current datasources are loosely defined, as such, a practitioner or external security team must carefully consider what the meaning of the datasource is, and how should they be used to assess the way a technique **could** potentially be detected by the offered guidance in the ATT&CK Matrix.

<br/>

!!! info  "Observation: Unclear Datasource Definition For DLL Telemetry"
    <br/>
    Run this query in the Mitre-Assistant

    === "From Unix"

        ```bash
        mitre-assistant search -m enterprise -t "stats:datasources" | grep -i "dll"
        ```

    === "From Windows"

        ```powershell
        mitre-assistant search -m enterprise -t "stats:datasources" | findstr "dll"
        ```

    **Notice** the output should give you 2 entries:  1) **dll-monitoring**, and 2) **loaded-dlls**


<br/>

The seasoned endpoint-security professional will quickly ask for the meaning of each category from the above query.  Because in the context of endpoint-security operations, monitoring DLLs boils down to a couple of things.

* **Runtime Context**:  When the DLL Loads into to the memory space of a process being executed
* **File IO Context**:  When the DLL structure is flushed and written to disk somewhere in the filesystem of the computer

Since the datasources provided by the Mitre ATT&CK Matrix are not well defined, then the context from above is unclear, **==specifically the dll-monitoring==** datasource.  If the Mitre ATT&CK Matrix would be suggesting the **==File IO Context==** is to be covered by the **dll-monitoring** datasource, then this conflicts with the separate datasource known as **==file-monitoring==**.

<br/>

!!! tip "Protip: Working With Datasources in ATT&CK"
    <br/>
    It is best to dump all of the active datasources in the ATT&CK Matrix and inspect each one of these, **==then==**, with your security team, conduct a few workshops to translate what Mitre has offered and map your own criteria to where  you find conflicts.

    <br/>
    For example:  A team dropped the **dll-monitoring** datasource and replaced it with **file-monitoring** datasource.

    Using Mitre-Assistant to dump all of the active datasources.

    ```bash
    mitre-assistant search -m enterprise -t "stats:datasources"
    ```

    ??? tldr "Output"

        ```markup
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | INDEX |             DATASOURCE             | TECHNIQUES | SUBTECHNIQUES | % TECHNIQUES | % SUBTECHNIQUES |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 1     | access-tokens                      |     2      |       6       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 2     | anti-virus                         |     6      |       4       |      4%      |       4%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 3     | api-monitoring                     |     42     |      61       |     23%      |       23%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 4     | application-logs                   |     9      |       6       |      5%      |       5%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 5     | asset-management                   |     2      |       0       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 6     | authentication-logs                |     29     |      54       |     16%      |       16%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 7     | aws-cloudtrail-logs                |     19     |      16       |     11%      |       11%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 8     | azure-activity-logs                |     18     |      15       |     10%      |       10%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 9     | binary-file-metadata               |     12     |      17       |      7%      |       7%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 10    | bios                               |     4      |       3       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 11    | browser-extensions                 |     1      |       0       |      1%      |       1%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 12    | component-firmware                 |     3      |       3       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 13    | data-loss-prevention               |     7      |       1       |      4%      |       4%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 14    | detonation-chamber                 |     1      |       2       |      1%      |       1%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 15    | digital-certificate-logs           |     0      |       1       |      0%      |       0%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 16    | disk-forensics                     |     2      |       3       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 17    | dll-monitoring                     |     17     |      36       |     10%      |       10%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 18    | dns-records                        |     3      |       5       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 19    | efi                                |     2      |       3       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 20    | email-gateway                      |     4      |       4       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 21    | environment-variable               |     5      |       4       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 22    | file-monitoring                    |     76     |      155      |     42%      |       42%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 23    | gcp-audit-logs                     |     2      |       5       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 24    | host-network-interface             |     4      |       4       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 25    | kernel-drivers                     |     5      |       2       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 26    | loaded-dlls                        |     10     |      27       |      6%      |       6%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 27    | mail-server                        |     4      |       8       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 28    | malware-reverse-engineering        |     3      |       4       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 29    | mbr                                |     3      |       2       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 30    | named-pipes                        |     2      |       0       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 31    | netflow-enclave-netflow            |     30     |      33       |     17%      |       17%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 32    | network-device-logs                |     8      |       7       |      5%      |       5%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 33    | network-intrusion-detection-system |     8      |       7       |      5%      |       5%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 34    | network-protocol-analysis          |     23     |      24       |     13%      |       13%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 35    | oauth-audit-logs                   |     4      |       2       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 36    | office-365-account-logs            |     4      |       7       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 37    | office-365-audit-logs              |     3      |       8       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 38    | office-365-trace-logs              |     2      |       2       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 39    | packet-capture                     |     33     |      36       |     18%      |       18%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 40    | powershell-logs                    |     9      |      14       |      5%      |       5%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 41    | process-command-line-parameters    |     78     |      164      |     43%      |       43%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 42    | process-monitoring                 |    131     |      260      |     72%      |       72%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 43    | process-use-of-network             |     35     |      31       |     20%      |       20%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 44    | sensor-health-and-status           |     1      |       3       |      1%      |       1%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 45    | services                           |     2      |       7       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 46    | ssl-tls-inspection                 |     10     |      14       |      6%      |       6%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 47    | stackdriver-logs                   |     17     |      15       |     10%      |       10%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 48    | system-calls                       |     6      |       6       |      4%      |       4%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 49    | third-party-application-logs       |     4      |       1       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 50    | user-interface                     |     3      |       3       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 51    | vbr                                |     2      |       2       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 52    | web-application-firewall-logs      |     3      |       5       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 53    | web-logs                           |     5      |       5       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 54    | web-proxy                          |     4      |       5       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 55    | windows-error-reporting            |     4      |       0       |      3%      |       3%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 56    | windows-event-logs                 |     29     |      34       |     16%      |       16%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 57    | windows-registry                   |     24     |      58       |     14%      |       14%       |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        | 58    | wmi-objects                        |     2      |       2       |      2%      |       2%        |
        +-------+------------------------------------+------------+---------------+--------------+-----------------+
        ```


    ??? tldr "Visualizing Data Sources in Google Datastudio"

        <iframe width="100%" height="450" src="https://datastudio.google.com/embed/reporting/fe0a2ae0-84f1-4a34-a45a-d46be22fc203/page/NYmkB" frameborder="0" style="border:0" allowfullscreen></iframe>