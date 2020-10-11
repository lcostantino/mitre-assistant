Search stats are built-in analysis logic created for all users of the **Mitre-Assistant** to provide immediate awareness of what the ATT&CK Matrix has, and with this information, assist leaders and tacticians in developing their own tactical plans or business objectives.

The **==stats==** search term is a special keyword used to create descriptive stats of several information categories. Let's review the stats guidelines before a purposeful deep-dive.

<br/>


!!! info "Mitre-Assistant | Stats Guidelines"

    All stats are accessed as a search term and **preceded with** the keyword `stats` and a **colon** ":"

    The following are the accepted search terms that represent statistics:

    ```bash
    mitre-assistant search -m enterprise -t "stats"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:datasources"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:platforms"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:tactics"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:techniques"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:subtechniques"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:adversaries"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:malware"
    ```

    ```bash
    mitre-assistant search -m enterprise -t "stats:tools"
    ```            
<br/>


 
!!! tldr "stats"
        
    ```bash
    mitre-assistant search -m enterprise -t "stats"
    ```

    This provides a high level of summary with **uniques** and **totals** of several categories.


<br/>


!!! tldr "stats:datasources"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:datasources"
        ```

        This provides a **==summary of the density==** of techniques mapped to each datasource.

        The numbers represented in this query are counts of the techniques where the datasource is cited by Mitre.    


<br/>

!!! tldr "stats:platforms"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:platforms"
        ```

        This provides a **==summary of the density==** of techniques mapped to each platform (Operating System).

        The numbers represented in this query are counts of the techniques where the platform is cited by Mitre.    


<br/>

!!! tldr "stats:tactics"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:tactics"
        ```

        This provides a **==summary of the density==** of techniques mapped to each tactic (killchain).

        The numbers represented in this query are counts of the techniques where the tactic is cited by Mitre. 


<br/>

!!! tldr "stats:techniques"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:techniques"
        ```
        This provides a **==summary of the density==** of techniques correlated to other criteria of interest.

        The numbers represented in this query are counts of the techniques where the technique is cited across several other information points as cited by Mitre.


<br/>

!!! tldr "stats:subtechniques"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:subtechniques"
        ```
        This provides a **==summary of the density==** of techniques correlated to other criteria of interest.

        The numbers represented in this query are counts of the techniques where the technique is cited across several other information points as cited by Mitre.


<br/>


!!! tldr "stats:adversaries"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:adversaries"
        ```

        This provides a **==summary of the density==** of techniques by adversary when correlated to other criteria of interest.

        The numbers represented in this query are counts of the techniques where the technique is cited across several other information points as cited by Mitre.


<br/>


!!! tldr "stats:malware"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:malware"
        ```

        This provides a **==summary of the density==** of techniques by malware when correlated to other criteria of interest.

        The numbers represented in this query are counts of the techniques where the technique is cited across several other information points as cited by Mitre.


<br/>

!!! tldr "stats:tools"
        
        ```bash
        mitre-assistant search -m enterprise -t "stats:tools"
        ```

        This provides a **==summary of the density==** of techniques by malware when correlated to other criteria of interest.

        The numbers represented in this query are counts of the techniques where the technique is cited across several other information points as cited by Mitre.


<br/>
