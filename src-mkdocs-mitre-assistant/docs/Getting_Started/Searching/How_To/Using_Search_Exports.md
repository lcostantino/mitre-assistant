The **Mitre-Assistant** was built for datapipeline workflows, so **CSV** and **JSON** are first class citizens!

First, lets review the export guidelines

!!! info "Mitre-Assistant | Exporting Guidelines"

    All exports are conducted by using the:

    `-e` or `--export-to` parameter and options of (CSV|JSON)

    Example: Export to CSV

    ```bash
    mitre-assistant search -m enterprise -t "t120" -e csv
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

