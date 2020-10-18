Before we dive into the practical tips, **==it is critical to understand==** the Mitre ATT&CK framework should not be considered the single source of truth, but rather, a source of excellent knowledge that is progressively making strides to bring security practitioners a common-language and possibly, common-sense.

I will be outlining the reasons why I believe this is the case.

## Empirical Context From External Contributions
The ATT&CK Matrix as published, derives its structure from many contributions of external opinions, analysis, and observations of various indviduals, organizations that provide security services, and likely the opinions of qualified individuals.  However, the data is partially incomplete.

!!! info "Observation: Adversary | Tai-Door - G0015"
    <br/>
    Run this query in the Mitre-Assistant.

    ```bash
    mitre-assistant search -m enterprise -t "taidoor" 
    ```

    **You will not find information of techniques** on this adversary although it is published in the matrix.

    Now, Reference these links from reputable sources on `taidoor`

    <a href="https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a" target="_blank" norelopener>US_CERT_TAIDOOR</a>

    <a href="https://www.securitymagazine.com/articles/92984-cisa-fbi-and-dod-issue-alert-on-taidoor-new-chinese-malware-variant"
       target="_blank" norelopener>SECURITY_MAGAZINE_TAIDOOR</a>

<br/>

The above example demonstrates the incompleteness of the information offered in the Matrix, therefore, **==this is not a criticism==** it is a factual observation for practitioners or security leaders to have present when working with the Matrix to pursue security outcomes.  Therefore, you must not follow the matrix blindly, instead you have to encourage your team(s) to scavenge or produce complementary information that can afford you the insights you are in need of when working with the approach suggested by the Mitre Corporation - i.e., emulate behaviors, record them, and formulate your own tactical plans based on the exhibited techniques of the adversary of malware you are investigating.