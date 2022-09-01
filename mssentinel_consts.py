# Login
SENTINEL_LOGIN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
SENTINEL_LOGIN_SCOPE = "https://management.azure.com/.default"

# Endpoint Routes and Parameters
SENTINEL_API_URL = "https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights"
SENTINEL_API_VERSION = "2022-08-01"
SENTINEL_API_INCIDENTS = "/incidents"
SENTINEL_API_INCIDENTS_PAGE_SIZE = 50

# State management
STATE_TOKEN_KEY = "sentinel_token"
STATE_LAST_TIME = "last_time"
STATE_FIRST_RUN = "first_run"

# JSON returned from Sentinel
SENTINEL_JSON_ACCESS_TOKEN = "access_token"
SENTINEL_JSON_VALUE = "value"
SENTINEL_JSON_NEXT_LINK = "nextLink"
SENTINEL_JSON_LAST_MODIFIED = "lastModifiedTimeUtc"

# JSON in app config

SENTINEL_APP_CONFIG_FIRST_RUN_MAX_INCIDENTS = "first_run_max_incidents"
SENTINEL_APP_CONFIG_START_TIME_SCHEDULED_POLL = "start_time_scheduled_poll"

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

LOG_UTC_SINCE_TIME_ERROR = "Please provide time in the span of UTC time since Unix epoch 1970-01-01T00:00:00Z."
LOG_GREATER_EQUAL_TIME_ERR = 'Invalid {0}, can not be greater than or equal to current UTC time'
LOG_CONFIG_TIME_POLL_NOW = "'Time range for POLL NOW' or 'Start Time for Schedule/Manual POLL' asset configuration parameter"

LOG_NO_LAST_MODIFIED_TIME = "Could not extract lastModifiedTimeUtc from latest ingested alert."