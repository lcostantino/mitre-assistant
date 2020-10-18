The **Mitre-Assistant** was built for datapipeline workflows, so **CSV** and **JSON** are first class citizens!

First, lets review the export guidelines

!!! info "Mitre-Assistant | Exporting Guidelines"

    All exports are conducted by using the:

    `-e` or `--export-to` parameter and options of (CSV|JSON)

    Example: Export to CSV

    ```bash
    mitre-assistant search -m enterprise -t "t1210" -e csv
    ```

    Example: Export CSV to Custom File

    ```bash
    mitre-assistant search -m enterprise -t "t1210" -e csv -f my_file.csv
    ```

    Example: Export to JSON

    ```bash
    mitre-assistant search -m enterprise -t "t1210" -e json
    ```

<br/>

## CSV Data Integrations

For most simple applications, the CSV export format should allow end-users to integrate the data with other existing workflows or approaches of achiving their analysis.

In the upcoming roadmap, the **Mitre-Assistant** will introduce features aligned to my individual approach of using the data to model criteria or searching for patterns.

**Stay Tuned!**