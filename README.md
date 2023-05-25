[comment]: # "Auto-generated SOAR connector documentation"
# Sentinel

Publisher: Splunk  
Connector Version: 2.0.0  
Product Vendor: Microsoft  
Product Name: Sentinel  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.0.0  

This app provides integration with Microsoft Sentinel

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2022-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
# Setup

## Authentication

### Microsoft Azure Application creation

This app requires creating a Microsoft Azure Application. To do so, navigate to
<https://portal.azure.com> in a browser and log in with a Microsoft account, then select **Azure
Active Directory** .

1.  Go to **App Registrations** and click on **+ New registration** .
2.  Give the app an appropriate name.
3.  Select a supported account type.
4.  Click on the **Register** .
    -   Under **Certificates & secrets** , add **New client secret** . Note this key somewhere
        secure, as it cannot be retrieved after closing the window.
    -   Under **Redirect URIs** we will be updating the entry of https://phantom.local to reflect
        the actual redirect URI. We will get this from the SOAR asset we create below in the section
        titled "Configure the Sentinel SOAR app Asset"

### Assign required Permission to the App Registration

1.  Under your subscription, In the menu bar, select the **Access control (IAM)** .
2.  Click on **+ Add** then select **Add role assignment** .
3.  On next page, Select **Microsoft Sentinel Contributor** role from **Role** section.
4.  In **Member** Section, Add Azure app which is created in earlier steps.
5.  Click on, Review + assign.

### Configure Sentinel SOAR app asset

When creating an asset for the **Sentinel** app, place the **Application ID** of the app created
during the previous step in the **Client ID** field and place the password generated during the app
creation process in the **Client Secret** field.

In order to connect to your Sentinel environment, the **Tenant ID** , **Subscription ID** ,
**Workspace Name** , **Workspace ID** and **Resource Group** fields are required. They can be found
inside of the Azure Portal.

In order to retrieve the above fields, navigate to your Sentinel Settings -> Go to Workspace
Settings, where all fields will be held.

Fields related to polling are optional.

Click on Save.

After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for Sentinel to this location** field and place it in the **Redirect URIs** field of
the Azure Application configuration page. To this URL, add **/result** . After doing so the URL
should look something like:

https://\<soar_host>/rest/handler/sentinel_e6434377-a3e4-4a5f-bfef-4f37e53e0676/\<asset_name>/result

  
Once again, click on Save.

# Usage

## How Sentinel handles identifiers

Actions like **get incident** take an *incident name* input parameter. This can be captured from the
Sentinel API or Web UI, but it's not to be confused with the Incident Number or the Title. The
Incident Name is the last component of the link to the incident that can be reviewed in Sentinel.
For example, the Incident Name corresponding to

          https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/dx582xwx-4x28-4f8d-9ded-9b0xd2803739/resourceGroups/demomachine_group/providers/Microsoft.OperationalInsights/workspaces/customworkspace/providers/Microsoft.SecurityInsights/Incidents/80289647-8743-4x67-87xx-9409x59xxxxx
        

is simply 80289647-8743-4x67-87xx-9409x59xxxxx.

## Run Query Action

### Query

The **query** parameter expects **KQL(Kusto Query Language)** type string as a input. Please find
some examples below.

-   For retrieving any table details

    Query: SecurityIncident

-   Fetch only N number of rows

    Query: TableName | take N

-   Sort data by any column

    Query: TableName | sort by Column1 desc | take 5

-   Use **where** key for find any specific column.

    Query: TableName | where Column1 == "Value1" and Column2 == "Value2"

    Query: TableName | where Column1 \>= ago(7d) | sort by Column2 desc | take 5

For more KQL queries, please refer [KQL
Overview](https://learn.microsoft.com/en-us/azure/sentinel/kusto-overview) .

### Timespan

The **timespan** parameter expects a [ISO 8061](https://en.wikipedia.org/wiki/ISO_8601#Durations)
duration. Please find some commonly used values below

-   **Last 7 days** : P7D
-   **Last 24 hours** : P1D
-   **Last 24 hours** : P1D
-   **Last 30 minutes:** : PT30M

### Post-Processing

The **run query** action will perform light post-processing of the raw results from Sentinel to ease
the use of data within SOAR. Notable, it will aggregate all returned tables in a single result set
and set the *SentinelTableName* property on the individual objects. Most of the time, there will
only be a *PrimaryResult* table returned.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Sentinel asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** |  required  | string | Tenant ID (e.g. 1e309abf-db6c-XXXX-a1d2-XXXXXXXXXXXX)
**subscription_id** |  required  | string | The ID of the target subscription
**resource_group_name** |  required  | string | The name of the resource group. The name is case insensitive
**workspace_name** |  required  | string | The name of the workspace
**workspace_id** |  required  | string | The id of the workspace
**client_id** |  required  | string | Application (client) ID assigned to your Graph Security API app
**client_secret** |  required  | password | Client Secret
**first_run_max_incidents** |  optional  | numeric | Maximum Incidents for scheduled polling first time
**start_time_scheduled_poll** |  optional  | string | Start Time for Schedule/Manual POLL (Use this format: 1970-01-01T00:00:00Z)
**non_interactive** |  optional  | boolean | Non-interactive

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality  
[get incident](#action-get-incident) - Get information of given incident  
[get incident entities](#action-get-incident-entities) - Get all entities for an incident  
[get incident alerts](#action-get-incident-alerts) - Get all alerts for an incident  
[list incidents](#action-list-incidents) - Get all incidents  
[update incident](#action-update-incident) - Updates an existing incident  
[add incident comment](#action-add-incident-comment) - Creates a new incident comment  
[run query](#action-run-query) - Queries the Sentinel Log Analytics workspace for data using KQL  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Callback action for the on_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get incident'
Get information of given incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** |  required  | Incident Name | string |  `mssentinel incident name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.incident_name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.etag | string |  |   "4c153924-1e22-4q91-98ca-130e9a05aa70" 
action_result.data.\*.id | string |  |  
action_result.data.\*.name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.additionalData.alertsCount | numeric |  |   1 
action_result.data.\*.properties.additionalData.bookmarksCount | numeric |  |   1 
action_result.data.\*.properties.additionalData.commentsCount | numeric |  |   6 
action_result.data.\*.properties.createdTimeUtc | string |  |   2023-05-12T10:17:19.7020255Z 
action_result.data.\*.properties.incidentNumber | numeric |  |   28 
action_result.data.\*.properties.incidentUrl | string |  `url`  |  
action_result.data.\*.properties.labels.\*.labelName | string |  |   Malicious 
action_result.data.\*.properties.labels.\*.labelType | string |  |   User 
action_result.data.\*.properties.lastModifiedTimeUtc | string |  |   2023-05-23T09:25:25.8130741Z 
action_result.data.\*.properties.owner.assignedTo | string |  |   Test user 
action_result.data.\*.properties.owner.email | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.owner.objectId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.owner.userPrincipalName | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.severity | string |  |   High 
action_result.data.\*.properties.status | string |  |   Active 
action_result.data.\*.properties.title | string |  |   Incident Rule 
action_result.data.\*.type | string |  |   org/Incidents 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully retrieved incident details 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get incident entities'
Get all entities for an incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** |  required  | Incident Name | string |  `mssentinel incident name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.incident_name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.entities.\*.id | string |  |  
action_result.data.\*.entities.\*.kind | string |  |   Url 
action_result.data.\*.entities.\*.name | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.entities.\*.properties.accountName | string |  |   soar 
action_result.data.\*.entities.\*.properties.additionalData.AvStatus | string |  |   Updated 
action_result.data.\*.entities.\*.properties.additionalData.DetonationFinalUrl | string |  |   testurl.com 
action_result.data.\*.entities.\*.properties.additionalData.DetonationVerdict | string |  |   GOOD 
action_result.data.\*.entities.\*.properties.additionalData.FQDN | string |  |   winatpc2 
action_result.data.\*.entities.\*.properties.additionalData.HealthStatus | string |  |   Active 
action_result.data.\*.entities.\*.properties.additionalData.LastExternalIpAddress | string |  |   8.8.8.8 
action_result.data.\*.entities.\*.properties.additionalData.LastIpAddress | string |  |   8.8.8.8 
action_result.data.\*.entities.\*.properties.additionalData.LastSeen | string |  |   2023-05-23T05:13:58.4852087Z 
action_result.data.\*.entities.\*.properties.additionalData.LoggedOnUsers | string |  |   [{"AccountName":"soar","DomainName":"WINATPC2"}] 
action_result.data.\*.entities.\*.properties.additionalData.MdatpDeviceId | string |  |   73a08e353cvf0294f733b7b6e9499439e433a1caf 
action_result.data.\*.entities.\*.properties.additionalData.OnboardingStatus | string |  |   Onboarded 
action_result.data.\*.entities.\*.properties.additionalData.RiskScore | string |  |   High 
action_result.data.\*.entities.\*.properties.address | string |  |   8.8.8.8 
action_result.data.\*.entities.\*.properties.algorithm | string |  |   SHA1 
action_result.data.\*.entities.\*.properties.commandLine | string |  |  
action_result.data.\*.entities.\*.properties.creationTimeUtc | string |  |   2022-11-29T06:36:26.7483096Z 
action_result.data.\*.entities.\*.properties.directory | string |  |  
action_result.data.\*.entities.\*.properties.elevationToken | string |  |   Limited 
action_result.data.\*.entities.\*.properties.fileName | string |  |   chrome.exe 
action_result.data.\*.entities.\*.properties.friendlyName | string |  |   testurl.com 
action_result.data.\*.entities.\*.properties.hashValue | string |  |   b443xb3ds119e21dc8xxxx9bbafeb6fc522ec044a 
action_result.data.\*.entities.\*.properties.hostName | string |  |   winatpc2 
action_result.data.\*.entities.\*.properties.isDomainJoined | boolean |  |   True  False 
action_result.data.\*.entities.\*.properties.ntDomain | string |  |   WINATPC2 
action_result.data.\*.entities.\*.properties.osFamily | string |  |   Windows 
action_result.data.\*.entities.\*.properties.osVersion | string |  |   22H2 
action_result.data.\*.entities.\*.properties.processId | string |  |   9644 
action_result.data.\*.entities.\*.properties.sid | string |  |   S-1-5-21-2166771715-3910420897-2790973560-1001 
action_result.data.\*.entities.\*.properties.url | string |  |   testsite.com 
action_result.data.\*.entities.\*.type | string |  |   org/Entities 
action_result.data.\*.metaData.\*.count | numeric |  |   2 
action_result.data.\*.metaData.\*.entityKind | string |  |   Url 
action_result.summary.total_entities | numeric |  |   1 
action_result.message | string |  |   Total Entities: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get incident alerts'
Get all alerts for an incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** |  required  | Incident Name | string |  `mssentinel incident name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.incident_name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.id | string |  `mssentinel alert id`  |  
action_result.data.\*.kind | string |  |   SecurityAlert 
action_result.data.\*.name | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.additionalData.OriginalProductComponentName | string |  |  
action_result.data.\*.properties.additionalData.OriginalProductName | string |  |  
action_result.data.\*.properties.alertDisplayName | string |  |   An active malware process was detected while executing 
action_result.data.\*.properties.alertLink | string |  |  
action_result.data.\*.properties.alertType | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.confidenceLevel | string |  |   Unknown 
action_result.data.\*.properties.description | string |  |   Malware and unwanted software are undesirable applications that perform annoying, disruptive, or harmful actions on affected machines. 
action_result.data.\*.properties.endTimeUtc | string |  |   2023-05-22T05:53:25.1335414Z 
action_result.data.\*.properties.friendlyName | string |  |   An active malware process was detected while executing 
action_result.data.\*.properties.processingEndTime | string |  |   2023-05-22T05:53:25.1335414Z 
action_result.data.\*.properties.productName | string |  |  
action_result.data.\*.properties.providerAlertId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70_1 
action_result.data.\*.properties.resourceIdentifiers.\*.type | string |  |   LogAnalytics 
action_result.data.\*.properties.resourceIdentifiers.\*.workspaceId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.severity | string |  |   Low 
action_result.data.\*.properties.startTimeUtc | string |  |   2023-05-22T05:53:25.1335414Z 
action_result.data.\*.properties.status | string |  |   New 
action_result.data.\*.properties.systemAlertId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.timeGenerated | string |  |   2023-05-22T05:53:25.1335414Z 
action_result.data.\*.properties.vendorName | string |  |  
action_result.data.\*.type | string |  |   org/Entities 
action_result.summary.total_alerts | numeric |  |   1 
action_result.message | string |  |   Total Alerts: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list incidents'
Get all incidents

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Maximum number of incidents to list (Default 100) | numeric | 
**filter** |  optional  | Filters the results, based on a Boolean condition | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.filter | string |  |   (properties/lastModifiedTimeUtc ge 2023-05-22T10:09:26Z) 
action_result.parameter.limit | numeric |  |   100 
action_result.data.\*.etag | string |  |   "4c153924-1e22-4q91-98ca-130e9a05aa70" 
action_result.data.\*.id | string |  |  
action_result.data.\*.name | string |  `mssentinel incident id`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.additionalData.alertProductNames | string |  |  
action_result.data.\*.properties.additionalData.alertsCount | numeric |  |   1 
action_result.data.\*.properties.additionalData.bookmarksCount | numeric |  |   3 
action_result.data.\*.properties.additionalData.commentsCount | numeric |  |   1 
action_result.data.\*.properties.additionalData.tactics | string |  |   InitialAccess 
action_result.data.\*.properties.createdTimeUtc | string |  |   2023-05-23T11:50:19.7705938Z 
action_result.data.\*.properties.description | string |  |   Incident generated 
action_result.data.\*.properties.firstActivityTimeUtc | string |  |   2023-05-22T11:45:27.946Z 
action_result.data.\*.properties.incidentNumber | numeric |  |   54 
action_result.data.\*.properties.incidentUrl | string |  `url`  |  
action_result.data.\*.properties.labels.\*.labelName | string |  |   Incident 
action_result.data.\*.properties.labels.\*.labelType | string |  |   User 
action_result.data.\*.properties.lastActivityTimeUtc | string |  |   2023-05-23T11:45:14.698Z 
action_result.data.\*.properties.lastModifiedTimeUtc | string |  |   2023-05-23T12:10:26.6664241Z 
action_result.data.\*.properties.owner.assignedTo | string |  |   Test User 
action_result.data.\*.properties.owner.email | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.owner.objectId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.owner.userPrincipalName | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.relatedAnalyticRuleIds | string |  |  
action_result.data.\*.properties.severity | string |  |   Medium 
action_result.data.\*.properties.status | string |  |   New 
action_result.data.\*.properties.title | string |  |   IncidentRule2 
action_result.data.\*.type | string |  |   org/Incidents 
action_result.summary.total_incidents | numeric |  |   5 
action_result.message | string |  |   Total incidents: 5 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update incident'
Updates an existing incident

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** |  required  | Incident Name | string |  `mssentinel incident name` 
**severity** |  optional  | Updated severity of the incident | string | 
**status** |  optional  | Updated status of the incident | string | 
**title** |  optional  | Updated title of the incident | string | 
**description** |  optional  | Updated description of the incident (Maximum 5000 Characters) | string | 
**owner_upn** |  optional  | Updated owner (userPrincipalName) | string | 
**labels** |  optional  | Labels relevant to this incident. Comma-seperated list allowed | string | 
**classification** |  optional  | The reason the incident was closed. Only updated when status is updated to Closed | string | 
**classification_comment** |  optional  | Describes the reason the incident was closed. Only updated when status is updated to Closed | string | 
**classification_reason** |  optional  | The classification reason the incident was closed with. Only updated when status is updated to Closed | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.classification | string |  |  
action_result.parameter.classification_comment | string |  |  
action_result.parameter.classification_reason | string |  |  
action_result.parameter.description | string |  |   Incidents for updation 
action_result.parameter.incident_name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.parameter.labels | string |  |   Tag1 
action_result.parameter.owner_upn | string |  |  
action_result.parameter.severity | string |  |   Medium 
action_result.parameter.status | string |  |   New 
action_result.parameter.title | string |  |   New Updated Incident 
action_result.data.\*.etag | string |  |   "4c153924-1e22-4q91-98ca-130e9a05aa70" 
action_result.data.\*.id | string |  |  
action_result.data.\*.name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.additionalData.alertsCount | numeric |  |   0 
action_result.data.\*.properties.additionalData.bookmarksCount | numeric |  |   0 
action_result.data.\*.properties.additionalData.commentsCount | numeric |  |   6 
action_result.data.\*.properties.createdTimeUtc | string |  |   2023-05-12T10:17:19.7020255Z 
action_result.data.\*.properties.description | string |  |   Incident for test alerts 
action_result.data.\*.properties.incidentNumber | numeric |  |   28 
action_result.data.\*.properties.incidentUrl | string |  `url`  |  
action_result.data.\*.properties.labels.\*.labelName | string |  |   Malicious 
action_result.data.\*.properties.labels.\*.labelType | string |  |   User 
action_result.data.\*.properties.lastModifiedTimeUtc | string |  |   2023-05-23T10:11:17.8367091Z 
action_result.data.\*.properties.owner.assignedTo | string |  |   Test User 
action_result.data.\*.properties.owner.email | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.owner.objectId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.owner.userPrincipalName | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.severity | string |  |   Medium 
action_result.data.\*.properties.status | string |  |   New 
action_result.data.\*.properties.title | string |  |   New Updated Incident 
action_result.data.\*.type | string |  |   org/Incidents 
action_result.summary | string |  |  
action_result.message | string |  |   Incident Updated Successfully 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'add incident comment'
Creates a new incident comment

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** |  required  | Incident Name | string |  `mssentinel incident name` 
**message** |  required  | The comment message (Upto 30,000 Characters) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.incident_name | string |  `mssentinel incident name`  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.parameter.message | string |  |   Update Owner 
action_result.data.\*.etag | string |  |   "4c153924-1e22-4q91-98ca-130e9a05aa70" 
action_result.data.\*.id | string |  |  
action_result.data.\*.name | string |  |   1684833925 
action_result.data.\*.properties.author.email | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.author.name | string |  |   User1 
action_result.data.\*.properties.author.objectId | string |  |   4c153924-1e22-4q91-98ca-130e9a05aa70 
action_result.data.\*.properties.author.userPrincipalName | string |  `email`  |   testuser@gmail.com 
action_result.data.\*.properties.createdTimeUtc | string |  |   2023-05-23T09:25:25.7863587Z 
action_result.data.\*.properties.lastModifiedTimeUtc | string |  |   2023-05-23T09:25:25.7863587Z 
action_result.data.\*.properties.message | string |  |   Update Owner and status 
action_result.data.\*.type | string |  |   org/Incidents/Comments 
action_result.summary | string |  |  
action_result.message | string |  |   Incident Updated Successfully 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'run query'
Queries the Sentinel Log Analytics workspace for data using KQL

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query in KQL (for example, "SecurityIncident" will retrieve the Sentinel incidents table) | string | 
**timespan** |  optional  | Time Interval in ISO 8601 Duration format. For example, "P7D" for last 7 days or an interval like "2007-03-01T13:00:00Z/2008-05-11T15:30:00Z" | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.query | string |  |   SecurityIncident | project AdditionalData, Comments, Title | summarize count() by Title 
action_result.parameter.timespan | string |  |  
action_result.data.\*.SentinelTableName | string |  |   PrimaryResult 
action_result.data.\*.TimeGenerated | string |  |  
action_result.data.\*.Title | string |  |   Suspicious activity found by incident on multiple endpoints 
action_result.data.\*.count_ | numeric |  |   5 
action_result.summary.total_rows | numeric |  |   30 
action_result.message | string |  |   Total rows: 30 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 