[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2022-2025 Splunk Inc."
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
