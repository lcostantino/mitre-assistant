This section provides a complete listing of the built-in search terms available in the Mitre-Assistant.

<br/>

| SEARCH TERM | PURPOSE |
|:------------|:--------|
<<<<<<< HEAD
|`{{ _platform_ }}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by platform type<br/></br/>Example:</br/>`search -m enterprise -t "linux"`<br/>Or<br/>`search -m enterprise -t "linux,macos"`|
|`{{ _datasource_ }}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by datasource type<br/></br/>Example:</br/>`search -m enterprise -t "windows-registry"`<br/>Or<br/>`search -m enterprise -t "wmi-objects,windows-registry"`|
|`{{ _tactic_ }}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by tactic/killchain<br/></br/>Example:</br/>`search -m enterprise -t "defense-evasion"`<br/>Or<br/>`search -m enterprise -t "defense-evasion,lateral-movement"`|
|`{{ _technique_name_}}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques matching a random word to the name of the technique/subtechnique<br/></br/>Example:</br/>`search -m enterprise -t "Exploit"`<br/>Or<br/>`search -m enterprise -t "Exploit,Services"`|
|`{{ _technique_id_ }}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by id<br/></br/>Example:</br/>`search -m enterprise -t "t1210"`<br/>Or<br/>`search -m enterprise -t "t1210,t1480"`|
|`{{ _subtechnique_id_}}`|**==Single Context and Multiple Input==**<br/>Search for subtechniques by id<br/></br/>Example:</br/>`search -m enterprise -t "t1574.010"`<br/>Or<br/>`search -m enterprise -t "t1574.010,t1574.011"`|
|`{{ _adversary_name_}}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by adversary<br/></br/>Example:</br/>`search -m enterprise -t "apt28"`<br/>Or<br/>`search -m enterprise -t "apt29,fin7"`|
|`{{ _malware_name_}}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by malware<br/></br/>Example:</br/>`search -m enterprise -t "boostwrite"`<br/>Or<br/>`search -m enterprise -t "boostwrite,griffon"`|
|`{{ _tool_name_}}`|**==Single Context and Multiple Input==**<br/>Search for techniques or subtechniques by tool<br/></br/>Example:</br/>`search -m enterprise -t "psexec"`<br/>Or<br/>`search -m enterprise -t "psexec,mimikatz"`|
|`deprecated`|Listing of **==Deprecated==** techniques|
|`revoked`|Listing of **==Revoked==** techniques with newly assigned technique IDs|
|`platforms`|Listing of **==all active==**  platforms within the enterprise matrix|
|`tactics`|Listing of **==all active==**  tactics/killchains within the enterprise matrix|
|`techniques`|Listing of **==all active==**  tecchniques within the enterprise matrix|
|`subtechniques`|Listing of **==all active==**  subtechniques within the enterprise matrix|
|`adversaries`|Listing of **==all active==**  adversaries within the enterprise matrix|
|`malware`|Listing of **==all active==**  malware within the enterprise matrix|
|`tools`|Listing of **==all active==**  tools within the enterprise matrix|
|`nosub`|Listing of **==all active==**  techniques **==without==** assigned subtechniques|
|`nodatasources`|Listing of **==all active==**  techniques **==without==** assigned datasources|
|`stats`|Summary stats with Uniques and Totals of the Mitre-Assistant Baseline|
|`stats:platforms`|Density of Techniques & Subtechniques By Assigned Platform|
|`stats:tactics`|Density of Techniques & Subtechniques By Assigned KillChain/Tactic|
|`stats:datasources`|Density of Techniques & Subtechniques By Assigned Datasource|
|`stats:techniques`|Density of Techniques mapped to other special criteria|
|`stats:subtechniques`|Density of Subtechniques mapped to other special criteria|
|`stats:adversaries`|Density of Techniques & Subtechniques By Assigned Adversary|
|`stats:malware`|Density of Techniques & Subtechniques By Assigned Malware|
|`stats:tools`|Density of Techniques & Subtechniques By Assigned Tool|
|`xref:datasources:platforms`|**==Experiimental==**<br/>2D Table Listing of datasources mapped to platforms<br/>|
|`xref:datasources:tactics`|**==Experiimental==**<br/>2D Table Listing of datasources mapped to tactics<br/>|


=======
|`stats`|Summarizes an Overview of Uniques and Totals for specific categories|
|`stats:platforms`|Summarizes the density of techniques assigned to platforms|
|`stats:datasources`|Summarizes the density of techniques assigned to datasources|
|`stats:tactics`|Summarizes the density of techniques assigned to tactics (killchains)|
|`stats:techniques`|Summarizes the density of **special** categories by each technique|
|`stats:subtechniques`|Summarizes the density of **special** categories by each subtechnique|
|`stats:adversaries`|Summarizes the density of **special** categories by each adversary group|
|`stats:malware`|Summatizes the density of **special** categories by each malware|
|`stats:tools`|Summarizes the density of **special** categories by each tool|
|`platforms`||
|`datasources`||
|`tactics`||
|`techniques`||
|`subtechniques`||
|`adversaries`||
|`malware`||
|`tools`||
|`deprecated`||
|`revoked`||
|`nosub`||
|`nodatasources`||
|`{{ _TID_ }}`||
|`{{ _PLATFORM }}`||
|`{{ _TACTIC_ }}`||
|`{{ _ADVERSARY_ }}`||
|`{{ _MALWARE_ }}`||
|`{{ _TOOL_ }}`||
>>>>>>> 4ae77997970e94acb92e97db14eee105c7d9f5c6
