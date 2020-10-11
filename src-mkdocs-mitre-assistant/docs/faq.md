# FAQ

## General

### **Are you associated, or employed by the Mitre Corporation?**
**==NO.==** I am not employed, associated, or affiliated with The Mitre Corporation.

<br/>

### **Is this tool created by The Mitre Corporation?**
**==NO.==** This tool **is not** created by The Mitre Corporation.  However this tool relies on the information published by The Mitre Corporation with reference to the ATT&CK Matrix.

<br/>

### **Is this tool commercial or require payment?**
**==NO.==** This tool is not commercial and it does not require payments from me or anyone else contributing to the code. If you are offered services, software claiming to be the tool named Mitre-Assistant, or using the same capabilities I am offering here as an open-source initiative, **==please report==** these to me via GitHub.

<br/>

### **Is this tool supported?**
**==YES.==** I am actively the creator and developer of the tool.  However, I accept contributions of code following the github PR approaches.  This project is built on my own time, and as such it is on a best effort basis.  Please read the LICENSE section.

<br/>

### **What Language is this tool created in?**
The tool in its current form, is a RUST program built across different platforms to support MACOS, LINUX DEBIAN, and WINDOWS.

<br/>
<hr/>

## Tool Usage

### **Is the ATT&CK Information Easily Updated?**
**==YES.==** The information can be updated at any time to keep-up with the Mitre ATT&CK CTI Repository.  However, I put the feature of updating in your hands, I do not run background jobs/tasks for the program to update the information.

To update the information you use the `download` and `baseline` subcommands like this:

!!! tip "Updating Information in Mitre-Assistant"
    
    Downloads the most current version of the ATT&CK CTI Repo

    ```bash
    mitre-assistant download -m enterprise
    ```

    Then, update the Mitre-Assistant Baseline

    ```bash
    mitre-assistant baseline -m enterprise
    ```    

<br/>

### **How different is your tool from the ATT&CK CTI Repo?**
My tool will give you a better experience consuming the CTI Repo, and you will benefit from the time savings of not having to create base queries for the fundamentals of working with the ATT&CK Matrix.  This includes, scenarios where you may not have someone in your team with the skills to code custom scripts for your reporting or modeling needs.

The CTI Repo gives you a client to consume its details, **==please, go ahead and use that==**, and **==then use the Mitre-Assistant==**, I am confident you will appreciate what I have accomplished and am now sharing with you, **==for free.==**
<br/>

### **If I use your tool in a commercial product, do I need to credit you?**
**==YES.==** In return for my passionate commitment to share with the world as others have done with me for my career, I ask that you do the right thing.  Although I understand some people are absent-minded or in some cases selfish, don't be deuche, do the right thing for others.


<br/>
<hr/>

## Contributing

### **Can I contribute code to your tool?**
**==YES.==* I welcome anyone understanding the benefit of contributing to this tool, go ahead and get your GitHub PR reviewed :)

<br/>

### **If I can't code, how can I contribute to your tool?**
**==NO PROBLEM!! I WELCOME YOU!!==** If you find yourself in any of the roles below, I am suggesting ways for you to get involved and be credited for your ideas, suggestions and efforts.

=== "Business Leader"
    ==If you have a need for leading metrics==, or business communication messaging stemming from the usage of the ATT&CK Matrix, I will gladly develop the logic so you and your team can have the data formatted and presented to you easily so you can pursue better business and security outcomes.

    Have your team submit a GitHub issue describing the need, and you can follow my progress on GitHub.

=== "Business Analyst"
    ==If you have a need for easy data access== so you can integrate with other reporting tools, feel free to submit a GitHub issue, I will help you as much as I can.

=== "Student"
    ==If you are in need of learning== about the ATT&CK Matrix, and you feel there aren't many tutorials covering good learning needs for you or your fellow students, feel free to submit a GitHub issue suggesting the learning format or knowledge goal.

    Or, if you already have a great way to learn, share it with others so we can teach the world together :)

=== "Consultant"
    ==If you are developing== methodologies for others to use in your engagements, and you cannot code, feel free to submit a request to have your workflow automated.

<br/>
<hr/>

## Security

### **How do I report a ==Security Vulnerability== with your tool?**

If you find a security vulnerability with my software, I **==urge you to quickly report it via github==**.  Please follow the security template approach so I can prioritize the security triage and reproduceability of the issue being presented.

