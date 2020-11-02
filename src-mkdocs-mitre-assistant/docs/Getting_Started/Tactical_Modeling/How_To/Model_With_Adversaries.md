??? tldr "TLDR - Online Application | Mitre-Assistant Adversaries Output"

    If you don't want to go through the tutorial, and just use the app, **click on the image**

    <a href="https://datastudio.google.com/reporting/c6a10bd0-5a59-4d71-afa6-e0d4000bc57a/page/DBnkB" target="_blank" norelopener>
        <img src="https://user-images.githubusercontent.com/11415591/96391451-af57f880-1186-11eb-9e21-a8795128d78d.png" />
    </a>


<br/>

## What you can build with Mitre-Assistant

With the Mitre-Assistant you can quickly turn the ATT&CK Matrix into meaningful visual representations for different needs, this is the reason I wanted the tool to support my needs and be an enabler for the needs of others.

In other words, Mitre-Assistant gives you the ability to ask the questions you want, access the data from those questions, and allow you to visualize it as you want/need.  I do not intend for the tool to be **opinionated** in the sense of how you should model data for your needs, rather, I try to be an enabler for you to get the data faster and reliably.

<br/>

??? tip "Protip:  Using Dendograms | Go Full Circle With Adversary Profiles"

    Circular Dendograms allow for the visualization of 2 or more data dimensions.

    Explore each tab for a visual representation of the Adversary -> Tactics -> Techniques

    **What do you ==conclude== from any of these visualizations in relation to the adversary?**
    
    <br/>

    === "APT1"
        <a href="https://user-images.githubusercontent.com/11415591/97118690-d3b15900-16e1-11eb-8489-faad71e5543d.png"
            target="_blank"
            norelopener>
            <img src="https://user-images.githubusercontent.com/11415591/97118690-d3b15900-16e1-11eb-8489-faad71e5543d.png" />
        </a>

    === "APT3"
        <a href="https://user-images.githubusercontent.com/11415591/97118593-33f3cb00-16e1-11eb-9f44-906b3f3288a1.png"
            target="_blank"
            norelopener>
            <img src="https://user-images.githubusercontent.com/11415591/97118593-33f3cb00-16e1-11eb-9f44-906b3f3288a1.png" />
        </a>
    
    === "APT29"

        <a href="https://user-images.githubusercontent.com/11415591/96589376-bed46000-12b2-11eb-8661-51118244ce21.png"
            target="_blank"
            norelopener>
            <img src="https://user-images.githubusercontent.com/11415591/96589376-bed46000-12b2-11eb-8661-51118244ce21.png" />
        </a>

    === "CARBANAK"

        <a href="https://user-images.githubusercontent.com/11415591/96590159-a7e23d80-12b3-11eb-9e8d-0bd2e39cbc6d.png"
            target="_blank"
            norelopener>
            <img src="https://user-images.githubusercontent.com/11415591/96590159-a7e23d80-12b3-11eb-9e8d-0bd2e39cbc6d.png" />
        </a>
    
    === "FIN7"

        <a href="https://user-images.githubusercontent.com/11415591/96589887-5cc82a80-12b3-11eb-8cc1-a0f1cc23299d.png"
            target="_blank"
            norelopener>
            <img src="https://user-images.githubusercontent.com/11415591/96589887-5cc82a80-12b3-11eb-8cc1-a0f1cc23299d.png" />
        </a>

    === "LAZARUS GROUP"

        <a href="https://user-images.githubusercontent.com/11415591/96588367-9009ba00-12b1-11eb-82b4-5902f6050053.png"
            target="_blank"
            norelopener>
            <img src="https://user-images.githubusercontent.com/11415591/96588367-9009ba00-12b1-11eb-82b4-5902f6050053.png" />
        </a>        

<br/>

## **Working With ATT&CK Adversary Datasets**
The ATT&CK enterprise CTI repository provides in its STIX JSON file specific keys that are called **relationships**.

As you begin to work with it, you will quickly understand there are releationships amongst ==adversaries== and ==techniques==, as well as relationships for the ==malware== and ==tools== objects.

The **Mitre-Assistant** streamlines your need for correlating these relationships yourself by hand, and it provides built-in queries for you to quickly
access the relationships. The current built-in queries map the following relationships.

!!! info "Mapping ATT&CK CTI Relationships"

	=== Adversary Relationships ===
		Adversary <--- TO ---> Technique
		Adversary <--- TO ---> Subtechnique
		Adversary <--- TO ---> Malware
		Adversary <--- TO ---> Tool

	=== Malware Relationships ===
		Malware <--- TO ---> Technique
		Malware <--- TO ---> Subtechnique
		Malware <--- TO ---> Adversary

	=== Tool Relationships ===
		Tool <--- TO ---> Technique
		Tool <--- TO ---> Subtechnique
		Tool <--- TO ---> Adversary

<br/>
The relationships above are made available to and user by launching queries based on either of the **adversary**, **malware**, **tool** entities, like this.

!!! info "Getting Relationships"

	=== By Adversary ===
		You can query by an adversary's name and you will see the entities of techniques, subtechniques, malware, and tools mapped for the
		adversary of interest.

		```bash
		mitre-assistant search -m enterprise -t "fin7"
		```

		??? tip "Output"

	=== By Malware ===
		You can query by a malware's name and you will also get the entities of techniques, subtechniques, and adversaries

		```bash
		mitre-assistant search -m enterprise -t "boostwrite"
		```

	=== By Tool ===
		You can query by a tool's name and you will also get the entiyies of techniques, subtechniques, and adversaries

		```bash
		mitre-assistant search -m enterprise -t "psexec"
		```

<br/>
