# CrowdStrike Falcon RTR scripts

These PowerShell scripts collect Sessions, Local Groups, User Rights Assignment, and NTLM registry settings from Windows hosts through CrowdStrike Falcon Real Time Response (RTR). They are required by the **BloodHound Enterprise CrowdStrike RTR Collector** Azure Marketplace application, which runs the scripts on hosts in your Falcon host groups and uploads the results to BloodHound Enterprise.

## Scripts

Upload each file to Falcon as a **cloud-hosted** RTR script. The **script name in Falcon must match the file name exactly**, including `.ps1`. These are the default names in the collector deployment wizard:

| File | What it collects |
| --- | --- |
| `fetch_session.ps1` | Active user sessions |
| `fetch_localgroups.ps1` | Local group membership |
| `fetch_userrights.ps1` | User rights assignments (LSA) |
| `fetch_ntlmregistry.ps1` | NTLM-related registry settings |

Do not rename the files after download unless you also change **Script File Names** in the collector wizard to the same names.

## Before you upload

- Use Windows hosts with the Falcon sensor, placed in one or more Falcon **host groups**.
- Scripts require **local Administrators** rights on the host. They also expect a **domain-joined** machine with line of sight to a domain controller.
- Falcon cloud scripts have a size limit (about 32,766 bytes). These files are under that limit; do not add large comments or extra content before upload.
- The collector API client needs at least: **Real-time Response (Admin): Write**, **Real-time Response: Read**, **Host Groups: Read**, and **Hosts: Read**.

## Upload in Falcon

1. Sign in to the Falcon console.
2. Open **Response scripts and files** (wording can vary by console version).
3. Create a **cloud** script for each `.ps1` file in this repository.
4. Set the Falcon script **name** to the file name from the table (for example `fetch_session.ps1`).
5. Upload the file contents and save.

Complete this upload **before** the first collector run. The collector does not upload scripts; it only runs names you already stored in Falcon.

## Collector wizard

On the **Script & Schedule Configuration** step, keep the default list unless you renamed scripts in Falcon:

`fetch_session.ps1, fetch_userrights.ps1, fetch_ntlmregistry.ps1, fetch_localgroups.ps1`

The collector executes each name as a Falcon cloud file with `-Silent`. After a run, confirm collection in the Azure Container Apps job logs and in BloodHound Enterprise.

## Support

For collector deployment and BloodHound upload issues, use BloodHound Enterprise Support (or the support contact on the Azure Marketplace offer). For script behavior, see the comment-based help at the top of each `.ps1` file.
