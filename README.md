[comment]: # "Auto-generated SOAR connector documentation"
# Sentinel

Publisher: Splunk Community  
Connector Version: 1\.0\.1  
Product Vendor: Microsoft  
Product Name: Sentinel  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.4  

This app provides integration with Microsoft Sentinel

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2022 Splunk Inc."
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

## Azure Configuration

### Create an App Registration

In order to configure the Sentinel app, a new App Registration in the Azure Portal is required.
Please refer to [Register an
Application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application)
for further guidance.

The Sentinel SOAR App uses the client-credentials flow to authenticate against Azure. Under your
created App registration, in Certificates & Secrets, create a new Client Secret. Save the secret
value for later use during asset configuration.

### Assign required Permissions to the App Registration

Under your subscription, select the **Add role assignment** context menu and assign the *Azure
Sentinel Contributor* role to your registered app.

### SOAR Configuration

When creating your SOAR asset, enter the Application ID as **Client ID** and the saved secret value
as **Client Secret** .

In order to connect to your Sentinel environment, the **Tenant ID** , **Subscription ID** ,
**Workspace Name** , **Workspace ID** , **Resource Group** fields are required. They can be found
inside of the Azure Portal. Fields related to polling are optional.

In order to retrieve the Workspace ID, navigate to your Sentinel Settings -> Workspace Settings

# Usage

## How Sentinel handles identifiers

Actions like **get incident** take an *incident name* input parameter. This can be captured from the
Sentinel API or Web UI, but it's not to be confused with the Incident Number or the Title. The
Incident Name is the last component of the link to the incident that can be reviewed in Sentinel.
For example, the Incident Name corresponding to

          https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/dx582xwx-4x28-4f8d-9ded-9b0xd2803739/resourceGroups/demomachine_group/providers/Microsoft.OperationalInsights/workspaces/customworkspace/providers/Microsoft.SecurityInsights/Incidents/80289647-8743-4x67-87xx-9409x59xxxxx
        

is simply 80289647-8743-4a67-87db-9409e597b0db

## Run Query

### Timerange

The **timerange** parameter expects a [ISO 8061](https://en.wikipedia.org/wiki/ISO_8601#Durations)
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
**tenant\_id** |  required  | string | Tenant ID \(e\.g\. 1e309abf\-db6c\-XXXX\-a1d2\-XXXXXXXXXXXX\)
**subscription\_id** |  required  | string | The ID of the target subscription
**resource\_group\_name** |  required  | string | The name of the resource group\. The name is case insensitive
**workspace\_name** |  required  | string | The name of the workspace
**workspace\_id** |  required  | string | The id of the workspace
**client\_id** |  required  | string | Application \(client\) ID assigned to your Graph Security API app
**client\_secret** |  required  | password | Client Secret
**first\_run\_max\_incidents** |  optional  | numeric | Maximum Incidents for scheduled polling first time
**start\_time\_scheduled\_poll** |  optional  | string | Start Time for Schedule/Manual POLL \(Use this format\: 1970\-01\-01T00\:00\:00Z\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  
[get incident](#action-get-incident) - Gets a given incident  
[get incident entities](#action-get-incident-entities) - Gets all entities for an incident  
[get incident alerts](#action-get-incident-alerts) - Gets all alerts for an incident  
[list incidents](#action-list-incidents) - Gets all incidents  
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
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_count** |  optional  | Number of events to generate | numeric | 
**artifact\_count** |  optional  | Number of artifacts to generate per event | numeric | 

#### Action Output
No Output  

## action: 'get incident'
Gets a given incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_name** |  required  | Incident Name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_name | string | 
action\_result\.data\.\*\.etag | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string |  `mssentinel incident name` 
action\_result\.data\.\*\.properties\.additionalData\.alertsCount | numeric | 
action\_result\.data\.\*\.properties\.additionalData\.bookmarksCount | numeric | 
action\_result\.data\.\*\.properties\.additionalData\.commentsCount | numeric | 
action\_result\.data\.\*\.properties\.createdTimeUtc | string | 
action\_result\.data\.\*\.properties\.incidentNumber | numeric | 
action\_result\.data\.\*\.properties\.incidentUrl | string | 
action\_result\.data\.\*\.properties\.labels\.\*\.labelName | string | 
action\_result\.data\.\*\.properties\.labels\.\*\.labelType | string | 
action\_result\.data\.\*\.properties\.lastModifiedTimeUtc | string | 
action\_result\.data\.\*\.properties\.owner\.assignedTo | string | 
action\_result\.data\.\*\.properties\.owner\.email | string | 
action\_result\.data\.\*\.properties\.owner\.objectId | string | 
action\_result\.data\.\*\.properties\.owner\.userPrincipalName | string | 
action\_result\.data\.\*\.properties\.severity | string | 
action\_result\.data\.\*\.properties\.status | string | 
action\_result\.data\.\*\.properties\.title | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.incident\_id | string |  `mssentinel incident id` 
action\_result\.summary\.incident\_name | string |  `mssentinel incident name` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident entities'
Gets all entities for an incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_name** |  required  | Incident Name | string |  `mssentinel incident name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_name | string | 
action\_result\.data\.entities\.\*\.id | string | 
action\_result\.data\.entities\.\*\.kind | string | 
action\_result\.data\.entities\.\*\.kind | string | 
action\_result\.data\.entities\.\*\.name | string | 
action\_result\.summary\.total\_entities | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident alerts'
Gets all alerts for an incident

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_name** |  required  | Incident Name | string |  `mssentinel incident name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_name | string | 
action\_result\.data\.\*\.id | string |  `mssentinel alert id` 
action\_result\.data\.\*\.kind | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.properties\.alertDisplayName | string | 
action\_result\.data\.\*\.properties\.confidenceLevel | string | 
action\_result\.data\.\*\.properties\.endTimeUtc | string | 
action\_result\.data\.\*\.properties\.friendlyName | string | 
action\_result\.data\.\*\.properties\.processingEndTime | string | 
action\_result\.data\.\*\.properties\.severity | string | 
action\_result\.data\.\*\.properties\.startTimeUtc | string | 
action\_result\.data\.\*\.properties\.status | string | 
action\_result\.data\.\*\.properties\.systemAlertId | string | 
action\_result\.data\.\*\.properties\.timeGenerated | string | 
action\_result\.data\.\*\.properties\.vendorName | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list incidents'
Gets all incidents

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  required  | Maximum number of incidents to list | numeric | 
**filter** |  optional  | Filters the results, based on a Boolean condition | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.etag | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string |  `mssentinel incident id` 
action\_result\.data\.\*\.properties\.additionalData\.alertsCount | numeric | 
action\_result\.data\.\*\.properties\.additionalData\.bookmarksCount | numeric | 
action\_result\.data\.\*\.properties\.additionalData\.commentsCount | numeric | 
action\_result\.data\.\*\.properties\.createdTimeUtc | string | 
action\_result\.data\.\*\.properties\.incidentNumber | numeric | 
action\_result\.data\.\*\.properties\.incidentUrl | string | 
action\_result\.data\.\*\.properties\.labels\.\*\.labelName | string | 
action\_result\.data\.\*\.properties\.labels\.\*\.labelType | string | 
action\_result\.data\.\*\.properties\.lastModifiedTimeUtc | string | 
action\_result\.data\.\*\.properties\.owner\.assignedTo | string | 
action\_result\.data\.\*\.properties\.owner\.email | string | 
action\_result\.data\.\*\.properties\.owner\.objectId | string | 
action\_result\.data\.\*\.properties\.owner\.userPrincipalName | string | 
action\_result\.data\.\*\.properties\.severity | string | 
action\_result\.data\.\*\.properties\.status | string | 
action\_result\.data\.\*\.properties\.title | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.total\_incidents | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update incident'
Updates an existing incident

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_name** |  required  | Incident Name | string | 
**severity** |  optional  | Updated severity of the incident | string | 
**status** |  optional  | Updated status of the incident | string | 
**title** |  optional  | Updated title of the incident | string | 
**description** |  optional  | Updated description of the incident | string | 
**owner\_upn** |  optional  | Updated owner \(userPrincipalName\) | string | 
**classification** |  optional  | The reason the incident was closed\. Only updated when status is updated to Closed | string | 
**classification\_comment** |  optional  | Describes the reason the incident was closed\. Only updated when status is updated to Closed | string | 
**classification\_reason** |  optional  | The classification reason the incident was closed with\. Only updated when status is updated to Closed | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.classification\_comment | string | 
action\_result\.parameter\.classification\_reason | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.incident\_name | string | 
action\_result\.parameter\.owner\_upn | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.title | string | 
action\_result\.data\.\*\.etag | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string |  `mssentinel incident name` 
action\_result\.data\.\*\.properties\.additionalData\.alertsCount | numeric | 
action\_result\.data\.\*\.properties\.additionalData\.bookmarksCount | numeric | 
action\_result\.data\.\*\.properties\.additionalData\.commentsCount | numeric | 
action\_result\.data\.\*\.properties\.createdTimeUtc | string | 
action\_result\.data\.\*\.properties\.incidentNumber | numeric | 
action\_result\.data\.\*\.properties\.incidentUrl | string | 
action\_result\.data\.\*\.properties\.labels\.\*\.labelName | string | 
action\_result\.data\.\*\.properties\.labels\.\*\.labelType | string | 
action\_result\.data\.\*\.properties\.lastModifiedTimeUtc | string | 
action\_result\.data\.\*\.properties\.owner\.assignedTo | string | 
action\_result\.data\.\*\.properties\.owner\.email | string | 
action\_result\.data\.\*\.properties\.owner\.objectId | string | 
action\_result\.data\.\*\.properties\.owner\.userPrincipalName | string | 
action\_result\.data\.\*\.properties\.severity | string | 
action\_result\.data\.\*\.properties\.status | string | 
action\_result\.data\.\*\.properties\.title | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.incident\_id | string |  `mssentinel incident id` 
action\_result\.summary\.incident\_name | string |  `mssentinel incident name` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add incident comment'
Creates a new incident comment

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_name** |  required  | Incident Name | string | 
**message** |  required  | The comment message | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_name | string | 
action\_result\.parameter\.message | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.properties\.author\.email | string | 
action\_result\.data\.\*\.properties\.author\.name | string | 
action\_result\.data\.\*\.properties\.author\.objectId | string | 
action\_result\.data\.\*\.properties\.author\.userPrincipalName | string | 
action\_result\.data\.\*\.properties\.createdTimeUtc | string | 
action\_result\.data\.\*\.properties\.lastModifiedTimeUtc | string | 
action\_result\.data\.\*\.properties\.message | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Queries the Sentinel Log Analytics workspace for data using KQL

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query in KQL \(for example, "SecurityIncident" will retrieve the Sentinel incidents table\) | string | 
**timespan** |  optional  | Time Interval in ISO 8601 Duration format\. For example, "P7D" for last 7 days or an interval like "2007\-03\-01T13\:00\:00Z/2008\-05\-11T15\:30\:00Z" | string | 
**max\_rows** |  required  | Maximum number of rows to return in the result\. Defaults to 3000 | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.status | string | 
action\_result\.parameter\.max\_rows | numeric | 
action\_result\.parameter\.query | string | 
action\_result\.parameter\.timespan | string | 
action\_result\.data\.\*\.TimeGenerated | string | 
action\_result\.summary\.total\_rows | numeric | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 