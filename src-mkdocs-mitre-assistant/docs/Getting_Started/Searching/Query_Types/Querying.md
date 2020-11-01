The **Mitre-Assistant** allows for search experiences with minimal effort, and in this article we will cover how you can leverage the flexible search types in the program.

<br/>

## **Search By Name**
When you want to find techniques by their name, the **Mitre-Assistant** uses a partial match, similar to a **contains** query in SQL or other common technologies.  Searching by name will allow you to find all the techniques that match your specific search.

!!! question "Example Search By Name: Boot"
    Find all techniques whose name has the word **boot**.

    ```bash
    mitre-assistant search -m enterprise -t "boot"
    ```

    ??? info "Output"

        <a href="https://user-images.githubusercontent.com/11415591/90316166-50f46c80-deee-11ea-8254-4630516086f2.png"
        target="_blank" norelopener>
        <img src="https://user-images.githubusercontent.com/11415591/90316166-50f46c80-deee-11ea-8254-4630516086f2.png"/>
        </a>

<br/>

## **Search By ID**
When you want to find techniques by their id, the **Mitre-Assistant** uses a **full match** with an **AND** condition when processing multiple inputs for technique or subtechnique IDs.

!!! question "Example Search By: ID"
    Find all techniques whose id values are:  **T1048**, **T1021**

    ```bash
    mitre-assistant search -m enterprise -t "t1021,t1048"
    ```

    ??? info "Output"

        <a href="https://user-images.githubusercontent.com/11415591/89109703-ae2def80-d411-11ea-9268-ab7f42527386.png"
        target="_blank" norelopener>
        <img src="https://user-images.githubusercontent.com/11415591/89109703-ae2def80-d411-11ea-9268-ab7f42527386.png"/>
        </a>

<br/>

## **Search By Deprecated**
When the Mitre Corporation updates the CTI repo, it can **deprecate*** techniques, this causes changes in their website to no longer have records for techniques you were once familiar with. For these reasons, the **Mitre-Assistant** makes it easy for you to quickly pull the deprecated techniques - Deprecated techniques appear to be removed from the Matrix from further usage.


!!! question "Example Search Deprecated Techniques"
    Find all techniques whose status has changed from `active` to ==deprecated==

    ```bash
    mitre-assistant search -m enterprise -t "deprecated"
    ```

    ??? info "Output"

        <a href="https://user-images.githubusercontent.com/11415591/97817714-11772a00-1c6c-11eb-9813-e0bca86fe7ca.png"
        target="_blank" norelopener>
        <img src="https://user-images.githubusercontent.com/11415591/97817714-11772a00-1c6c-11eb-9813-e0bca86fe7ca.png"/>
        </a>

<br/>

## **Search By Revoked**
When the Mitre Corporation updates the CTI repo, it can revoke techniques, this causes changes in their website to no longer have records for techniques you were once familiar with. For these reasons, the **Mitre-Assistant** makes it easy for you to quickly pull the techniques revoked, and the new assignment provided by the Mitre Corporation.

This query is very useful for service providers who might have code-bases with naming conventions aligned to the ATT&CK matrix, it helps to quickly know how to update the old techniques (revoked) for the newly assigned IDs.

!!! question "Example Search Revoked Techniques"
    Find all techniques whose status has changed from `active` to ==revoked==

    ```bash
    mitre-assistant search -m enterprise -t "revoked"
    ```

    ??? info "Output"

        <a href="https://user-images.githubusercontent.com/11415591/93018273-839c8e00-f59c-11ea-9ee0-2490b870fbf0.png"
        target="_blank" norelopener>
        <img src="https://user-images.githubusercontent.com/11415591/93018273-839c8e00-f59c-11ea-9ee0-2490b870fbf0.png"/>
        </a>

<br/>