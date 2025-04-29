# Sentinel

Publisher: Splunk Community \
Connector Version: 1.0.2 \
Product Vendor: Microsoft \
Product Name: Sentinel \
Minimum Product Version: 5.3.4

This app provides integration with Microsoft Sentinel

### Configuration variables

This table lists the configuration variables required to operate Sentinel. These variables are specified when configuring a Sentinel asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** | required | string | Tenant ID (e.g. 1e309abf-db6c-XXXX-a1d2-XXXXXXXXXXXX) |
**subscription_id** | required | string | The ID of the target subscription |
**resource_group_name** | required | string | The name of the resource group. The name is case insensitive |
**workspace_name** | required | string | The name of the workspace |
**workspace_id** | required | string | The id of the workspace |
**client_id** | required | string | Application (client) ID assigned to your Graph Security API app |
**client_secret** | required | password | Client Secret |
**first_run_max_incidents** | optional | numeric | Maximum Incidents for scheduled polling first time |
**start_time_scheduled_poll** | optional | string | Start Time for Schedule/Manual POLL (Use this format: 1970-01-01T00:00:00Z) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity \
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality \
[get incident](#action-get-incident) - Gets a given incident \
[get incident entities](#action-get-incident-entities) - Gets all entities for an incident \
[get incident alerts](#action-get-incident-alerts) - Gets all alerts for an incident \
[list incidents](#action-list-incidents) - Gets all incidents \
[update incident](#action-update-incident) - Updates an existing incident \
[add incident comment](#action-add-incident-comment) - Creates a new incident comment \
[run query](#action-run-query) - Queries the Sentinel Log Analytics workspace for data using KQL

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Callback action for the on_poll ingest functionality

Type: **ingest** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_count** | optional | Number of events to generate | numeric | |
**artifact_count** | optional | Number of artifacts to generate per event | numeric | |

#### Action Output

No Output

## action: 'get incident'

Gets a given incident

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** | required | Incident Name | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.incident_name | string | | |
action_result.data.\*.etag | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | `mssentinel incident name` | |
action_result.data.\*.properties.additionalData.alertsCount | numeric | | |
action_result.data.\*.properties.additionalData.bookmarksCount | numeric | | |
action_result.data.\*.properties.additionalData.commentsCount | numeric | | |
action_result.data.\*.properties.createdTimeUtc | string | | |
action_result.data.\*.properties.incidentNumber | numeric | | |
action_result.data.\*.properties.incidentUrl | string | | |
action_result.data.\*.properties.labels.\*.labelName | string | | |
action_result.data.\*.properties.labels.\*.labelType | string | | |
action_result.data.\*.properties.lastModifiedTimeUtc | string | | |
action_result.data.\*.properties.owner.assignedTo | string | | |
action_result.data.\*.properties.owner.email | string | | |
action_result.data.\*.properties.owner.objectId | string | | |
action_result.data.\*.properties.owner.userPrincipalName | string | | |
action_result.data.\*.properties.severity | string | | |
action_result.data.\*.properties.status | string | | |
action_result.data.\*.properties.title | string | | |
action_result.data.\*.type | string | | |
action_result.summary.incident_id | string | `mssentinel incident id` | |
action_result.summary.incident_name | string | `mssentinel incident name` | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get incident entities'

Gets all entities for an incident

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** | required | Incident Name | string | `mssentinel incident name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.incident_name | string | `mssentinel incident name` | |
action_result.data.entities.\*.id | string | | |
action_result.data.entities.\*.kind | string | | |
action_result.data.entities.\*.kind | string | | |
action_result.data.entities.\*.name | string | | |
action_result.summary.total_entities | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get incident alerts'

Gets all alerts for an incident

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** | required | Incident Name | string | `mssentinel incident name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.incident_name | string | `mssentinel incident name` | |
action_result.data.\*.id | string | `mssentinel alert id` | |
action_result.data.\*.kind | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.properties.alertDisplayName | string | | |
action_result.data.\*.properties.confidenceLevel | string | | |
action_result.data.\*.properties.endTimeUtc | string | | |
action_result.data.\*.properties.friendlyName | string | | |
action_result.data.\*.properties.processingEndTime | string | | |
action_result.data.\*.properties.severity | string | | |
action_result.data.\*.properties.startTimeUtc | string | | |
action_result.data.\*.properties.status | string | | |
action_result.data.\*.properties.systemAlertId | string | | |
action_result.data.\*.properties.timeGenerated | string | | |
action_result.data.\*.properties.vendorName | string | | |
action_result.data.\*.type | string | | |
action_result.summary.total_alerts | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list incidents'

Gets all incidents

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** | required | Maximum number of incidents to list | numeric | |
**filter** | optional | Filters the results, based on a Boolean condition | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.filter | string | | |
action_result.parameter.limit | numeric | | |
action_result.data.\*.etag | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | `mssentinel incident id` | |
action_result.data.\*.properties.additionalData.alertsCount | numeric | | |
action_result.data.\*.properties.additionalData.bookmarksCount | numeric | | |
action_result.data.\*.properties.additionalData.commentsCount | numeric | | |
action_result.data.\*.properties.createdTimeUtc | string | | |
action_result.data.\*.properties.incidentNumber | numeric | | |
action_result.data.\*.properties.incidentUrl | string | | |
action_result.data.\*.properties.labels.\*.labelName | string | | |
action_result.data.\*.properties.labels.\*.labelType | string | | |
action_result.data.\*.properties.lastModifiedTimeUtc | string | | |
action_result.data.\*.properties.owner.assignedTo | string | | |
action_result.data.\*.properties.owner.email | string | | |
action_result.data.\*.properties.owner.objectId | string | | |
action_result.data.\*.properties.owner.userPrincipalName | string | | |
action_result.data.\*.properties.severity | string | | |
action_result.data.\*.properties.status | string | | |
action_result.data.\*.properties.title | string | | |
action_result.data.\*.type | string | | |
action_result.summary.total_incidents | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'update incident'

Updates an existing incident

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** | required | Incident Name | string | |
**severity** | optional | Updated severity of the incident | string | |
**status** | optional | Updated status of the incident | string | |
**title** | optional | Updated title of the incident | string | |
**description** | optional | Updated description of the incident | string | |
**owner_upn** | optional | Updated owner (userPrincipalName) | string | |
**classification** | optional | The reason the incident was closed. Only updated when status is updated to Closed | string | |
**classification_comment** | optional | Describes the reason the incident was closed. Only updated when status is updated to Closed | string | |
**classification_reason** | optional | The classification reason the incident was closed with. Only updated when status is updated to Closed | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.classification | string | | |
action_result.parameter.classification_comment | string | | |
action_result.parameter.classification_reason | string | | |
action_result.parameter.description | string | | |
action_result.parameter.incident_name | string | | |
action_result.parameter.owner_upn | string | | |
action_result.parameter.severity | string | | |
action_result.parameter.status | string | | |
action_result.parameter.title | string | | |
action_result.data.\*.etag | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | `mssentinel incident name` | |
action_result.data.\*.properties.additionalData.alertsCount | numeric | | |
action_result.data.\*.properties.additionalData.bookmarksCount | numeric | | |
action_result.data.\*.properties.additionalData.commentsCount | numeric | | |
action_result.data.\*.properties.createdTimeUtc | string | | |
action_result.data.\*.properties.incidentNumber | numeric | | |
action_result.data.\*.properties.incidentUrl | string | | |
action_result.data.\*.properties.labels.\*.labelName | string | | |
action_result.data.\*.properties.labels.\*.labelType | string | | |
action_result.data.\*.properties.lastModifiedTimeUtc | string | | |
action_result.data.\*.properties.owner.assignedTo | string | | |
action_result.data.\*.properties.owner.email | string | | |
action_result.data.\*.properties.owner.objectId | string | | |
action_result.data.\*.properties.owner.userPrincipalName | string | | |
action_result.data.\*.properties.severity | string | | |
action_result.data.\*.properties.status | string | | |
action_result.data.\*.properties.title | string | | |
action_result.data.\*.type | string | | |
action_result.summary.incident_id | string | `mssentinel incident id` | |
action_result.summary.incident_name | string | `mssentinel incident name` | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.parameter.ph | ph | | |
action_result.parameter.ph2 | ph | | |

## action: 'add incident comment'

Creates a new incident comment

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident_name** | required | Incident Name | string | |
**message** | required | The comment message | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.incident_name | string | | |
action_result.parameter.message | string | | |
action_result.data.\*.id | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.properties.author.email | string | | |
action_result.data.\*.properties.author.name | string | | |
action_result.data.\*.properties.author.objectId | string | | |
action_result.data.\*.properties.author.userPrincipalName | string | | |
action_result.data.\*.properties.createdTimeUtc | string | | |
action_result.data.\*.properties.lastModifiedTimeUtc | string | | |
action_result.data.\*.properties.message | string | | |
action_result.data.\*.type | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'run query'

Queries the Sentinel Log Analytics workspace for data using KQL

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | Query in KQL (for example, "SecurityIncident" will retrieve the Sentinel incidents table) | string | |
**timespan** | optional | Time Interval in ISO 8601 Duration format. For example, "P7D" for last 7 days or an interval like "2007-03-01T13:00:00Z/2008-05-11T15:30:00Z" | string | |
**max_rows** | required | Maximum number of rows to return in the result. Defaults to 3000 | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.status | string | | success failed |
action_result.parameter.max_rows | numeric | | |
action_result.parameter.query | string | | |
action_result.parameter.timespan | string | | |
action_result.data.\*.TimeGenerated | string | | |
action_result.summary.total_rows | numeric | | |
action_result.message | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
