# Overview

A more flexible, useful, and cooler ATT&CK CTI with team-wide collaboration in-mind has arrived!

The Mitre-Assistant surfaced as a collaboration tool amongst many people and skillsets that needed to work with The Mitre Corporation's ATT&CK Matrix.

We needed to expedite both tactical and strategic business plans between security experts and business leaders to support both customers and security community forums.  We realized the ecosystem of utilities in the public domain were incomplete, or not capable of offering us the flexibility we were
looking for in the pursuit of our security and business objectives.

The main purpose of this utility is to reduce friction between business professionals and the ATT&CK Matrix.

<div align="center"><strong>I hope you find this contribution useful in your own business setting.</strong></div>
<br/>

## **What does it do?**
<hr/>
The Mitre-Assistant at its core is a command-line utility intended to be used for data pipeline workflows to power several applications.  It parses the Mitre STIX CTI Repository into a more intuitive and friendlier JSON format, and present insightful information to users of the ATT&CK Matrix.

The tool offers a flexible set of features to allow for the quick extraction of desired information from the ATT&CK Matrix.  

!!! tip "ProTip:  Experiment | Get Techniques By Specific Datasource & Tactic"
    Try to obtain all of the techniques that can be detected with the `api-monitoring` datasource.

    When you get there, and don'ty find an easy way to do this yourself immediately, now you can use the mitre assistant like this:

    ```bash
    mitre-assistant search -m enterprise -t "api-monitoring"
    ```

    And filter with our favorite tools by the ones on the `Lateral Movement` tactic

    ```bash
    mitre-assistant search -m enterprise -t "api-monitoring" | grep -i "lateral-movement"
    ```

For a complete listing of the features or capabilities offered in Mitre-Assistant, please refer to the <a href="/features/" target="_blank" norelopener><strong>Features Section</strong></a>

<br/>


## **How does it help?**
<hr/>

!!! tip "For Both Strategic and Tactical Planning"
    If you are practitioner in charge of managing a technical security program, you will need to model and design detection coverage programs based on the ATT&CK Matrix.  This utility will save tons of time, I guarantee it.  You will be able to **==slice & dice==** the matrix by different views, criteria as you share information with your team and external partners.

    You are able to export your queries to **JSON** and **CSV**.

!!! tip "For Threat Modeling"
    If you are in a particular industry, for example in Finance, and you need to quickly know all of the `FIN` adversaries according to the
    ATT&CK Matrix, what do they do, which malware do they use, and what techniques are attributed to these for your own emulation plans, then please don't waste time, look at this below.

    ```bash
    mitre-assistant search -m enterprise -t "fin4,fin5,fin6,fin7,fin8,fin10"
    ```

    This query above will bring you all of the existing information for all of those adversaries, and produce a table like this below.

    ??? info "Query Output"
        Snippet

        ![image](https://user-images.githubusercontent.com/11415591/95679475-1b43cb00-0ba1-11eb-8988-d26b29d3960f.png)

<br/>

## **Where can I get it?**
<hr/>
The utility can obtained from the <a href="https://github.com/dfirence/mitre-assistant/releases" target="_blank" norelopener><strong>releases section</strong></a> of the Github repo where it is being actively developed, or if you are a `rustlang` user, you can just install via the cargo package manager.

!!! tip "Installing via Cargo"

    ```bash
    cargo install mitre-assistant
    ```

<br/>