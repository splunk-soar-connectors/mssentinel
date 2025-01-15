# File: mssentinel_consts.py
#
# Copyright (c) 2022-2025 Splunk Inc.
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
MS_SENTINEL_LOGIN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
MS_SENTINEL_LOGIN_SCOPE = "https://management.azure.com/.default"
LOGANALYTICS_LOGIN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/token"
LOGANALYTICS_LOGIN_RESOURCE = "https://api.loganalytics.io"
MS_SENTINEL_AUTHORIZE_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
MS_SENTINEL_CODE_GENERATION_SCOPE = "offline_access https://management.core.windows.net//user_impersonation"


# Endpoint Routes and Parameters
MS_SENTINEL_API_URL = "https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/\
{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights"

MS_SENTINEL_API_VERSION = "2022-08-01"
MS_SENTINEL_API_INCIDENTS = "/incidents"
MS_SENTINEL_API_INCIDENTS_ALERTS = "/alerts"
MS_SENTINEL_API_INCIDENTS_ENTITIES = "/entities"
MS_SENTINEL_DEFAULT_SIZE = 100

LOGANALYTICS_API_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"

# State management
STATE_LAST_TIME = "last_time"
STATE_FIRST_RUN = "first_run"

# JSON returned from Sentinel
MS_SENTINEL_JSON_VALUE = "value"
MS_SENTINEL_JSON_NEXT_LINK = "nextLink"
MS_SENTINEL_JSON_LAST_MODIFIED = "lastModifiedTimeUtc"
MS_SENTINEL_TOKEN_STRING = "token"
MS_SENTINEL_REFRESH_TOKEN_STRING = "refresh_token"
MS_SENTINEL_ACCESS_TOKEN_STRING = "access_token"
MS_SENTINEL_LOGANALYTICS_TOKEN_KEY = "loganalytics_token"

# JSON in app config
FIRST_RUN_MAX_INCIDENTS = "first_run_max_incidents"
START_TIME_SCHEDULED_POLL = "start_time_scheduled_poll"
MAX_INCIDENTS_DEFAULT = 100
DATE_STR_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# messages
MS_REST_URL_NOT_AVAILABLE_MESSAGE = "Rest URL not available. Error: {error}"
MS_SENTINEL_RETRIEVING_ACCESS_TOKEN_MESSAGE = "Retrieving access token"
MS_SENTINEL_SUCCESS_RETRIEVING_ACCESS_TOKEN = "Successfully retrieved access token"
MS_SENTINEL_FAILED_RETRIEVING_ACCESS_TOKEN = "Failed to retrieve new access token"
MS_SENTINEL_FAILED_RETRIEVING_INCIDENTS = "Failed to retrieve incidents"
MS_SENTINEL_FAILED_RETRIEVING_INCIDENT = "Failed to retrieve incident"
MS_SENTINEL_FAILED_UPDATE_INCIDENT = "Failed to update incident"
MS_SENTINEL_FAILED_RETRIEVING_INCIDENT_ALERTS = "Failed to retrieve incident alerts"
MS_SENTINEL_FAILED_RETRIEVING_INCIDENT_ENTITIES = "Failed to retrieve incident entities"
MS_SENTINEL_FAILED_CREATING_INCIDENT_COMMENT = "Failed to create incident comment"
MS_SENTINEL_TEST_CONNECTIVITY_PASSED = "Test Connectivity Passed"
MS_SENTINEL_TEST_CONNECTIVITY_FAILED = "Test Connectivity Failed"
MS_SENTINEL_BASE_URL_NOT_FOUND_MESSAGE = "SOAR Base URL not found in System Settings. " "Please specify this value in System Settings."
MS_SENTINEL_CONNECTIVITY_PROCESS = "Please connect to the following URL from a different tab to continue the connectivity process"
MS_SENTINEL_AUTHORIZE_TROUBLESHOOT_MESSAGE = (
    "If authorization URL fails to communicate with your SOAR instance, check whether you have:  "
    " 1. Specified the Web Redirect URL of your App -- The Redirect URL should be <POST URL>/result . "
    " 2. Configured the base URL of your SOAR Instance at Administration -> Company Settings -> Info"
)
MS_SENTINEL_ERROR_MESSAGE_UNKNOWN = "Unknown error occurred. Please check the asset configuration and|or action parameters."
MS_OAUTH_URL_MESSAGE = "Using OAuth URL:\n"
MS_STATE_FILE_ERROR_MESSAGE = "Unable to load state file"
MS_AUTHORIZATION_ERROR_MESSAGE = "Authorization code not received or not given"
MS_SENTINEL_STATE_FILE_CORRUPT_ERROR = (
    "Error occurred while loading the state file due to it's unexpected format. "
    "Resetting the state file with the default format. Please run the test connectivity."
)

MS_SENTINEL_UTC_SINCE_TIME_ERROR = "Please provide time in the span of UTC time since Unix epoch 1970-01-01T00:00:00Z."
MS_SENTINEL_GREATER_EQUAL_TIME_ERROR = "Invalid {0}, can not be greater than or equal to current UTC time"
MS_SENTINEL_CONFIG_TIME_POLL_NOW = "'Time range for POLL NOW' or 'Start Time for Schedule/Manual POLL' asset configuration parameter"
MS_SENTINEL_INVALID_DATE_FORMAT = "Invalid date string received. Error occurred while checking date format. Error: {}"
MS_SENTINEL_NO_LAST_MODIFIED_TIME = "Could not extract lastModifiedTimeUtc from latest ingested incident."
MS_SENTINEL_STATE_FILE_ERROR = "Unexpected details retrieved from the state file. please run the test connectivity"
MS_SENTINEL_DUPLICATE_CONTAINER_MESSAGE = "Duplicate container found"
MS_SENTINEL_CONTAINER_ERROR_MESSAGE = "Error occurred while saving the container: ID {}: {}"
MS_SENTINEL_ARTIFACT_ERROR_MESSAGE = "Error occurred while saving the artifact(s): {}"
MS_SENTINEL_TOKEN_EXPIRED_MESSAGE = [
    "token is invalid",
    "token has expired",
    "ExpiredAuthenticationToken",
    "AuthenticationFailed",
    "TokenExpired",
    "InvalidAuthenticationToken",
]
MS_SENTINEL_FAILED_LOGANALYTICS_QUERY = "Failed request to query log analytics workspace"
MS_SENTINEL_VALID_INT_MESSAGE = "Please provide a valid integer value in the '{param}'"
MS_SENTINEL_NON_NEG_INT_MESSAGE = "Please provide a valid non-negative integer value in the '{param}'"
MS_SENTINEL_NON_NEG_NON_ZERO_INT_MESSAGE = "Please provide a valid non-zero positive integer value in '{param}'"
MS_SENTINEL_VALID_LABEL_PARAM = "Please provide a valid tag values in the '{param}' parameter"
MS_SENTINEL_NO_PARAMETER_MESSAGE = "Please provide at least one parameter for update"

MS_SENTINEL_WAIT_TIME = 5
MS_TC_STATUS_SLEEP = 3
MS_SENTINEL_EMPTY_RESPONSE_CODES = [200, 204]
MS_SENTINEL_BAD_REQUEST_CODE = 400
MS_SENTINEL_NOT_FOUND_CODE = 404
MS_SENTINEL_DEFAULT_TIMEOUT = 30
