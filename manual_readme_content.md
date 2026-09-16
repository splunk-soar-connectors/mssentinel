# Setup

## Azure configuration

### Create an app registration

To configure the Sentinel app, create an app registration in the Azure portal. See [Register an
application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
for instructions.

The Sentinel app uses the client credentials flow to authenticate with Azure. In the app
registration, select **Certificates & secrets** and create a client secret. Save the secret value
for the Splunk SOAR asset configuration.

### Assign permissions to the app registration

Under your Azure subscription, select **Add role assignment** and assign the *Microsoft Sentinel
Contributor* role to the app registration.

### Configure Splunk SOAR

When you create the Splunk SOAR asset, enter the application ID in **Client ID** and the saved
secret value in **Client Secret**.

Enter values for **Tenant ID**, **Subscription ID**, **Workspace Name**, **Workspace ID**, and
**Resource Group**. Find these values in the Azure portal. Polling fields are optional.

To find the workspace ID, in Microsoft Sentinel, select **Settings > Workspace settings**.

# Usage

## Sentinel incident identifiers

Actions such as **get incident** require an **incident name**. You can retrieve the incident name
from the Sentinel API or web interface. The incident name is not the incident number or title. It
is the final component of the incident URL. For example:

```text
https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/dx582xwx-4x28-4f8d-9ded-9b0xd2803739/resourceGroups/demomachine_group/providers/Microsoft.OperationalInsights/workspaces/customworkspace/providers/Microsoft.SecurityInsights/Incidents/80289647-8743-4a67-87db-9409e597b0db
```

The incident name in this example is `80289647-8743-4a67-87db-9409e597b0db`.

## Run query

### Time range

The `timespan` parameter accepts an [ISO 8601
duration](https://en.wikipedia.org/wiki/ISO_8601#Durations). Common values include:

- **Last 7 days:** `P7D`
- **Last 24 hours:** `P1D`
- **Last 30 minutes:** `PT30M`

### Post-processing

The **run query** action combines all tables returned by Sentinel into one result set and adds the
`SentinelTableName` property to each object. Most responses contain only a `PrimaryResult` table.
