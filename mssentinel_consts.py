# File: mssentinel_consts.py
#
# Copyright (c) 2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
# Login
SENTINEL_LOGIN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
SENTINEL_LOGIN_SCOPE = "https://management.azure.com/.default"
LOGANALYTICS_LOGIN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/token"
LOGANALYTICS_LOGIN_RESOURCE = "https://api.loganalytics.io"


# Endpoint Routes and Parameters
SENTINEL_API_URL = "https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/\
{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights"

SENTINEL_API_VERSION = "2022-08-01"
SENTINEL_API_INCIDENTS = "/incidents"
SENTINEL_API_INCIDENTS_PAGE_SIZE = 50

LOGANALYTICS_API_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"

# State management
STATE_TOKEN_KEY = "sentinel_token"
STATE_LAST_TIME = "last_time"
STATE_FIRST_RUN = "first_run"
STATE_LOGANALYTICS_TOKEN_KEY = "loganalytics_token"

# JSON returned from Sentinel
SENTINEL_JSON_ACCESS_TOKEN = "access_token"
SENTINEL_JSON_VALUE = "value"
SENTINEL_JSON_NEXT_LINK = "nextLink"
SENTINEL_JSON_LAST_MODIFIED = "lastModifiedTimeUtc"

# JSON in app config

SENTINEL_APP_CONFIG_FIRST_RUN_MAX_INCIDENTS = "first_run_max_incidents"
SENTINEL_APP_CONFIG_START_TIME_SCHEDULED_POLL = "start_time_scheduled_poll"
SENTINEL_APP_CONFIG_MAX_ARTIFACTS_DEFAULT = 500
SENTINEL_APP_CONFIG_MAX_INCIDENTS_DEFAULT = 1000

SENTINEL_APP_DT_STR_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


LOG_RETRIEVING_ACCESS_TOKEN = "Retrieving access token"
LOG_SUCCESS_RETRIEVING_ACCESS_TOKEN = "Successfully retrieved access token"
LOG_FAILED_RETRIEVING_ACCESS_TOKEN = "Failed to retrieve new access token"
LOG_FAILED_RETRIEVING_INCIDENTS = "Failed to retrieve incidents"
LOG_FAILED_RETRIEVING_INCIDENT = "Failed to retrieve incident"
LOG_FAILED_UPDATE_INCIDENT = "Failed to update incident"
LOG_FAILED_RETRIEVING_INCIDENT_ALERTS = "Failed to retrieve incident alerts"
LOG_FAILED_RETRIEVING_INCIDENT_ENTITIES = "Failed to retrieve incident entities"
LOG_CONNECTING_TO = "Connecting to {to}"
LOG_FAILED_CREATING_INCIDENT_COMMENT = "Failed to create incident comment"

LOG_UTC_SINCE_TIME_ERROR = "Please provide time in the span of UTC time since Unix epoch 1970-01-01T00:00:00Z."
LOG_GREATER_EQUAL_TIME_ERR = 'Invalid {0}, can not be greater than or equal to current UTC time'
LOG_CONFIG_TIME_POLL_NOW = "'Time range for POLL NOW' or 'Start Time for Schedule/Manual POLL' asset configuration parameter"

LOG_NO_LAST_MODIFIED_TIME = "Could not extract lastModifiedTimeUtc from latest ingested incident."
LOG_NO_VALUE = "Could not extract value from latest ingested incidents."
LOG_ERROR_MSG_UNKNOWN = "Unknown error occurred. Please check the asset configuration and|or action parameters."
LOG_TOKEN_EXPIRED_MSG = ["The access token is invalid", "ExpiredAuthenticationToken", "InvalidTokenError"]
LOG_FAILED_PARSING_MAX_ROWS = "Failed to parse max_rows parameter - a positive integer is required"
LOG_FAILED_PARSING_LIMIT = "Failed to parse limit parameter - a positive integer is required"
LOG_FAILED_LOGANALYTICS_QUERY = "Failed request to query log analytics workspace"
