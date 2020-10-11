Searching with the Mitre-Assistant is super easy, and fast.  But you need to keep in mind a few things:

!!!info "Searching Guidelines"

    All searches are conducted by using the:

    `search` subcommand

    `-m` or `--matrix` parameter

    `-t` or `--term` paramer

    <br/>

    Example

    ```bash
    mitre-assistant search -m enterprise -t "t1210"
    ```

<br/>

## Queries and Single Context

In Mitre-Assistant, a `single-context` means you are searching for a specific category (context).  Users commonly search for various categories (contexts), such as:

* Techniques by ID Number
* Techniques by Name
* Techniques by Killchain or Tactic Type
* Techniques by Platform (operating system)
* Techniques by Datasource
* Techniques by Adversary
* Techniques by Malware Name
* ... etc ...


Each of the above category is what Mitre-Assistant understands as `single context` queries. The **great news** here is that you can search for all of those categories (contexts) without having to instruct the Mitre-Assistant that this is what you want!

Let's take a look at the various examples of how to search with minimal effort:

<br/>

!!! tip "Mitre Assistant | Single Context Search Examples"

    === "By ID"

        Assumes you want Technique ID 1210 - T1210

        ```bash
        mitre-assistant search -m enterprise -t "t1210"
        ```

        <br/>

        **Notice** your query by ID is case insensitive!

    === "By Name"

        Assumes you want Techniques with the keyword `Exploitation`

        ```bash
        mitre-assistant search -m enterprise -t "Exploitation"
        ```

    === "By Tactic"

        Assumes you want Techniques assigned to the `Lateral Movement` Tactic

        ```bash
        mitre-assistant search -m enterprise -t "lateral-movement"
        ```

    === "By Platform"

        Assumes you want Techniques assigned to the `LINUX` Platform

        ```bash
        mitre-assistant search -m enterprise -t "linux"
        ```

    === "By Datasource"

        Assumes you want Techniques assigned to the `Api Monitoring` datasource

        ```bash
        mitre-assistant search -m enterprise -t "api-monitoring"
        ```

    === "By Adversary"

        Assumes you want Techniques assigned to the `FIN7` Adversary

        ```bash
        mitre-assistant search -m enterprise -t "fin7"
        ```

    === "By Malware"

        Assumes you want Techniques assigned to the `Boostwrite` Malware

        ```bash
        mitre-assistant search -m enterprise -t "boostwrite"
        ```

<br/>

## Single Context Queries With Multiple Inputs

Now that single context is understood, we need to show what multiple inputs look like.  In Mitre-Assistant `multiple inputs` are dead simple!

You just add a comma `","` character to your query.

!!! tip "Mitre Assistant | Multiple Input Search Examples"

    === "By ID"

        Assumes you want techniques: T1210, T1480,T1550

        ```bash
        mitre-assistant search -m enterprise -t "t1210,t1480,t1550"
        ```

    === "By Name"

        Assumes you want Techniques with the keywords: `Exploitation` or `Component`

        ```bash
        mitre-assistant search -m enterprise -t "Exploitation,Component"
        ```

    === "By Tactic"

        Assumes you want Techniques assigned to the `Lateral Movement` or `Initial Access` Tactics

        ```bash
        mitre-assistant search -m enterprise -t "lateral-movement,initial-access"
        ```

    === "By Platform"

        Assumes you want Techniques assigned to the `LINUX` or `MAC OS` Platforms

        ```bash
        mitre-assistant search -m enterprise -t "macos,linux"
        ```

    === "By Datasource"

        Assumes you want Techniques assigned to the `Api Monitoring` or `Process Monitoring` Datasources

        ```bash
        mitre-assistant search -m enterprise -t "api-monitoring,process-monitoring"
        ```

    === "By Adversary"

        Assumes you want Techniques assigned to the `FIN7` or `APT29` Adversaries

        ```bash
        mitre-assistant search -m enterprise -t "fin7,apt29"
        ```

    === "By Malware"

        Assumes you want Techniques assigned to the `Boostwrite` or `Griffon` Malware

        ```bash
        mitre-assistant search -m enterprise -t "boostwrite,griffon"
        ```

<br/>

## Roadmap Ahead:  Multiple Contexts

As you have learned, it is already very powerful to be able to search by single context categories.  You can already slice and dice the ATT&CK Matrix in ways the website cannnot support you.  However, this is not the only way I am aiming for Mitre-Assistant to work.

Stay tuned for more features and capabilities being added to the Mitre-Assistant!