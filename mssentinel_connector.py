#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals
from sys import api_version
from time import time
from urllib.parse import urlparse
from mssentinel_consts import *
from datetime import datetime, timedelta

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup


def _get_error_message_from_exception(e):
    error_code = None
    error_msg = LOG_ERROR_MSG_UNKNOWN

    try:
        if hasattr(e, "args"):
            if len(e.args) > 1:
                error_code = e.args[0]
                error_msg = e.args[1]
            elif len(e.args) == 1:
                error_msg = e.args[0]
    except Exception:
        pass

    if not error_code:
        error_text = "Error Message: {}".format(error_msg)
    else:
        error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

    return error_text


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

class SentinelConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SentinelConnector, self).__init__()

        self._state = None

        self._tenant_id = None
        self._subscription_id = None
        self._client_id = None
        self._client_secret = None
        self._workspace_name = None
        self._resource_group_name = None
        self._login_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _check_invalid_since_utc_time(self, action_result, time):
        """Determine that given time is not before 1970-01-01T00:00:00Z.
        Parameters:
            :param action_result: object of ActionResult class
            :param time: object of time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Check that given time must not be before 1970-01-01T00:00:00Z.
        if time < datetime.strptime("1970-01-01T00:00:00Z", SENTINEL_APP_DT_STR_FORMAT):
            return phantom.APP_ERROR
        return phantom.APP_SUCCESS

    def _check_date_format(self, action_result, date):
        """Validate the value of time parameter given in the action parameters.
        Parameters:
            :param date: value of time(start/end/reference) action parameter
        Returns:
            :return: status(True/False)
        """
        # Initialize time for given value of date
        time = None
        try:
            # Check for the time is in valid format or not
            time = datetime.strptime(date, SENTINEL_APP_DT_STR_FORMAT)
            # Taking current UTC time as end time
            end_time = datetime.utcnow()
            # Check for given time is not before 1970-01-01T00:00:00Z
            ret_val = self._check_invalid_since_utc_time(action_result, time)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, LOG_UTC_SINCE_TIME_ERROR)
            # Checking future date
            if time >= end_time:
                msg = LOG_GREATER_EQUAL_TIME_ERR.format(LOG_CONFIG_TIME_POLL_NOW)
                return action_result.set_status(phantom.APP_ERROR, msg)
        except Exception as e:
            message = "Invalid date string received. Error occurred while checking date format. Error: {}".format(str(e))
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_txt = _get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(error_txt))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", verify=True, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        try:
            r = request_func(
                endpoint,
                verify=verify,
                **kwargs
            )

        except Exception as e:
            error_txt = _get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(error_txt))
                ), resp_json)

        return self._process_response(r, action_result)

    def _make_loganalytics_query(self, action_result, method="post", **kwargs):        
        endpoint = f"{self._loganalytics_api_url}"

        if not "headers" in kwargs:
            kwargs["headers"] = {}

        access_token = self._state[STATE_LOGANALYTICS_TOKEN_KEY]
        kwargs["headers"]["Authorization"] = f"Bearer {access_token}"

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, method, **kwargs)

        for msg in LOG_TOKEN_EXPIRED_MSG:
            if msg in action_result.get_message():
                status = self._generate_new_loganalytics_access_token(action_result=action_result)

                if phantom.is_fail(status):
                    return action_result.get_status(), None

                kwargs["headers"]["Authorization"] = f"Bearer {self._state[STATE_LOGANALYTICS_TOKEN_KEY]}"
                return self._make_rest_call(endpoint, action_result, method, **kwargs)

        return ret_val, resp_json

    def _make_sentinel_call(self, endpoint, action_result, method="get", **kwargs):

        if not "params" in kwargs:
            kwargs["params"] = {}
        
        #TODO: this does not work on subsequent requests because its in the nextLink URL already -find a better way

        parsed_endpoint = urlparse(endpoint)
        if not "api-version" in parsed_endpoint.query:
            kwargs["params"]["api-version"] = "2022-08-01"
 
        if not "headers" in kwargs:
            kwargs["headers"] = {}

        access_token = self._state[STATE_TOKEN_KEY]
        kwargs["headers"]["Authorization"] = f"Bearer {access_token}"

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, method, **kwargs)

        # If token is expired, generate new token and re-execute last call
        for msg in LOG_TOKEN_EXPIRED_MSG:
            if msg in action_result.get_message():
                status = self._generate_new_access_token(action_result=action_result)

                if phantom.is_fail(status):
                    return action_result.get_status(), None

                kwargs["headers"]["Authorization"] = f"Bearer {self._state[STATE_TOKEN_KEY]}"
                return self._make_rest_call(endpoint, action_result, method, **kwargs)

        return ret_val, resp_json

    def _make_paginated_sentinel_call(self, endpoint, action_result, params, limit):
        
        results_list = []
        next_link = ''

        while True:
            if next_link:
                endpoint = next_link
                params = {}

            ret_val, res_json = self._make_sentinel_call(endpoint, action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            if SENTINEL_JSON_VALUE not in res_json:
                return phantom.APP_ERROR, LOG_NO_VALUE

            for entry in res_json[SENTINEL_JSON_VALUE]:
                results_list.append(entry)
            
            if int(limit) > len(results_list):
                results_list = results_list[:limit]

            if not res_json.get(SENTINEL_JSON_NEXT_LINK):
                break

            next_link = res_json[SENTINEL_JSON_NEXT_LINK]

        return phantom.APP_SUCCESS, results_list


    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        self.save_progress(LOG_RETRIEVING_ACCESS_TOKEN)
        self.save_progress(LOG_CONNECTING_TO.format(to=self._login_url))

        ret_val = self._generate_new_access_token(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_ACCESS_TOKEN)
            return action_result.get_status()

        self.save_progress(LOG_SUCCESS_RETRIEVING_ACCESS_TOKEN)

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}"

        ret_val, resp_json = self._make_sentinel_call(endpoint, action_result, params={"$top": 1})

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENTS)
            return action_result.get_status()


        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)
    
    def _handle_list_incidents(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        limit = int(param["limit"])
        filter = param.get("filter")

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}"

        params = {
            "$top": SENTINEL_API_INCIDENTS_PAGE_SIZE
        }

        if filter:
            params["$filter"] = filter

        ret_val, incident_list = self._make_paginated_sentinel_call(endpoint, action_result, params, limit)
        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENTS)
            return action_result.get_status()

        for incident in incident_list:
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary["total_incidents"] = len(incident_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_for_existing_container(self, action_result, key):
            """Check for existing container and return container ID and remaining margin count.
            Parameters:
                :param action_result: object of ActionResult class
                :param key: Source Data ID of the container to check
            Returns:
                :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR),
                        cid(container_id),
                        count(remaining margin calculated with given _max_artifacts)
            """
            cid = None
            count = None

            base_url = self.get_phantom_base_url()
            base_url = base_url if base_url.endswith('/') else base_url + '/'
            url = f'{base_url}rest/container?_filter_source_data_identifier="{key}"&sort=start_time&order=desc'

            try:
                r = requests.get(url, verify=False)
            except Exception as e:
                self.debug_print("Error making local rest call: {0}".format(str(e)))
                self.debug_print('DB QUERY: {}'.format(url))
                return phantom.APP_ERROR, cid, count

            try:
                resp_json = r.json()
            except Exception as e:
                self.debug_print('Exception caught: {0}'.format(str(e)))
                return phantom.APP_ERROR, cid, count

            container = resp_json.get('data', [])
            if not container:
                self.debug_print("Not having any existing container")
                return phantom.APP_ERROR, cid, count

            # Consider latest container as existing container from the received list of containers
            try:
                container = container[0]
                if not isinstance(container, dict):
                    self.debug_print("Invalid response received while checking for the existing container")
                    return phantom.APP_ERROR, cid, count
            except Exception as e:
                self.debug_print("Invalid response received while checking for the existing container. Error: {}".format(str(e)))
                return phantom.APP_ERROR, cid, count

            cid = container.get('id')
            artifact_count = container.get('artifact_count')

            self.debug_print("Existing Container ID: {}".format(cid))
            self.debug_print("Existing Container artifacts count: {}".format(artifact_count))

            try:
                count = int(self._max_artifacts) - int(artifact_count)
                # Not having space in latest container or exceed a configured limit for artifacts
                if count <= 0:
                    self.debug_print("Not having enough space for the artifacts in the existing container")
                    cid = None
                    count = None
            except Exception as e:
                self.debug_print("Error occurred while calculating remaining container space. Error: {}".format(str(e)))
                cid = None
                count = None
            return phantom.APP_SUCCESS, cid, count

    def _save_artifacts(self, action_result, results, name, key):
        """Ingest all the given artifacts accordingly into the new or existing container.
        Parameters:
            :param action_result: object of ActionResult class
            :param results: list of artifacts of IoCs or alerts results
            :param name: name of the container in which data will be ingested
            :param key: source ID of the container in which data will be ingested
        Returns:
            :return: None
        """
        # Initialize
        cid = None
        start = 0
        count = None

        # If not results return
        if not results:
            return

        # Check for existing container only if it's a scheduled/interval poll and not first run
        if not (self.is_poll_now() or self._state['first_run']):
            ret_val, cid, count = self._check_for_existing_container(action_result, key)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to check for existing container")

        if cid and count:
            ret_val = self._ingest_artifacts(action_result, results[:count], name, key, cid=cid)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to save ingested artifacts in the existing container")
                return
            # One part is ingested
            start = count

        # Divide artifacts list into chunks which length equals to max_artifacts configured in the asset
        artifacts = [results[i:i + self._max_artifacts] for i in range(start, len(results), self._max_artifacts)]

        for artifacts_list in artifacts:
            ret_val = self._ingest_artifacts(action_result, artifacts_list, name, key)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to save ingested artifacts in the new container")
                return

    def _ingest_artifacts(self, action_result, artifacts, name, key, cid=None):
        """Ingest artifacts into the Phantom server.
        Parameters:
            :param action_result: object of ActionResult class
            :param artifacts: list of artifacts
            :param name: name of the container in which data will be ingested
            :param key: source ID of the container in which data will be ingested
            :param cid: value of container ID
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.debug_print(f"Ingesting {len(artifacts)} artifacts for {key} results into the {'existing' if {cid} else 'new'} container")
        ret_val, message, cid = self._save_ingested(action_result, artifacts, name, key, cid=cid)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to save ingested artifacts, error msg: {}".format(message))
            return ret_val

        return phantom.APP_SUCCESS

    def _save_ingested(self, action_result, artifacts, name, key, cid=None):
        """Save the artifacts into the given container ID(cid) and if not given create new container with given key(name).
        Parameters:
            :param action_result: object of ActionResult class
            :param artifacts: list of artifacts of IoCs or incidents results
            :param name: name of the container in which data will be ingested
            :param key: source ID of the container in which data will be ingested
            :param cid: value of container ID
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), message, cid(container_id)
        """
        artifacts[-1]["run_automation"] = True
        if cid:
            for artifact in artifacts:
                artifact['container_id'] = cid
            ret_val, message, _ = self.save_artifacts(artifacts)
            self.debug_print("save_artifacts returns, value: {}, reason: {}".format(ret_val, message))
        else:
            container = dict()
            container.update({
                "name": name,
                "description": 'incident ingested using MS Sentinel API',
                "source_data_identifier": key,
                "artifacts": artifacts
            })
            ret_val, message, cid = self.save_container(container)
            self.debug_print("save_container (with artifacts) returns, value: {}, reason: {}, id: {}".format(ret_val, message, cid))
        return ret_val, message, cid

    def _create_incident_artifacts(self, action_result, incident):
        artifacts = []

        incident_artifact = {}
        incident_artifact['label'] = 'incident'
        incident_artifact['name'] = 'incident Artifact'
        incident_artifact['source_data_identifier'] = incident.get('name')
        incident_artifact['data'] = incident

        cef = incident
        incident_artifact['cef'] = cef
        # Append to the artifacts list
        artifacts.append(incident_artifact)

        return artifacts

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        config = self.get_config()

        start_time_scheduled_poll = config.get(SENTINEL_APP_CONFIG_START_TIME_SCHEDULED_POLL)
        last_modified_time = (datetime.now() - timedelta(days=7)).strftime(SENTINEL_APP_DT_STR_FORMAT) # Let's fall back to the last 7 days
        self._max_artifacts = config.get("max_artifacts", SENTINEL_APP_CONFIG_MAX_ARTIFACTS_DEFAULT)
        incidents = []
        max_incidents = SENTINEL_APP_CONFIG_MAX_INCIDENTS_DEFAULT

        if not self._state.get(STATE_TOKEN_KEY):
            self._generate_new_access_token(action_result)

        if start_time_scheduled_poll:
            ret_val = self._check_date_format(action_result, start_time_scheduled_poll)
            if phantom.is_fail(ret_val):
                self.save_progress(action_result.get_message())
                return action_result.set_status(phantom.APP_ERROR)
            last_modified_time = start_time_scheduled_poll
        
        if self.is_poll_now():
            max_incidents = param[phantom.APP_JSON_CONTAINER_COUNT]

        elif self._state.get(STATE_FIRST_RUN, True):
            self._state[STATE_FIRST_RUN] = False
            max_incidents = int(config.get(SENTINEL_APP_CONFIG_FIRST_RUN_MAX_INCIDENTS, max_incidents))
        else:
            if self._state.get(STATE_LAST_TIME):
                last_modified_time = self._state[STATE_LAST_TIME]

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}"
    
        filter = f"(properties/lastModifiedTimeUtc gt {last_modified_time})"

        params = {
            "$filter": filter,
            "$top": SENTINEL_API_INCIDENTS_PAGE_SIZE
        }

        ret_val, incidents = self._make_paginated_sentinel_call(endpoint, action_result, params, max_incidents)
        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENTS)
            return action_result.get_status()

        self.save_progress(f"Successfully fetched {len(incidents)} incidents.")

        # Ingest the incidents
        for incident in incidents:
            try:
                # Create artifacts from the incidents
                artifacts = self._create_incident_artifacts(action_result, incident)
            except Exception as e:
                self.debug_print("Error occurred while creating artifacts for incidents. Error: {}".format(str(e)))
                # Make incidents as empty list
                incidents = list()

            # Save artifacts for incidents
            try:
                self._save_artifacts(action_result, artifacts, name=incident["properties"]["title"], key=incident["name"])
            except Exception as e:
                self.debug_print("Error occurred while saving artifacts for incidents. Error: {}".format(str(e)))

        summary = action_result.update_summary({})
        summary["total_incidents"] = len(incidents)
        summary["filter"] = filter
        summary["first_run"] = self._state.get(STATE_FIRST_RUN, True)

        if incidents:
            if SENTINEL_JSON_LAST_MODIFIED not in incidents[0]["properties"]:
                return action_result.set_status(phantom.APP_ERROR, LOG_NO_LAST_MODIFIED_TIME)

            self._state[STATE_LAST_TIME] = incidents[0]["properties"][SENTINEL_JSON_LAST_MODIFIED]
            self.save_state(self._state)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident_alerts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}/{incident_name}/alerts"

        ret_val, alerts_response = self._make_sentinel_call(endpoint, action_result, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENT_ALERTS)
            return action_result.get_status()

        if "value" in alerts_response:
            for alert in alerts_response["value"]:
                action_result.add_data(alert)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Could not extract alerts from response")

        summary = action_result.update_summary({})
        summary["total_alerts"] = len(alerts_response["value"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident_entities(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}/{incident_name}/entities"

        ret_val, entities_response = self._make_sentinel_call(endpoint, action_result, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENT_ALERTS)
            return action_result.get_status()

        action_result.add_data(entities_response) 

        summary = action_result.update_summary({})
        summary["total_entities"] = len(entities_response["entities"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}/{incident_name}"

        ret_val, incident = self._make_sentinel_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENT)
            return action_result.get_status()

        action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary["incident_id"] = incident["id"]
        summary["incident_name"] = incident["name"]
 

        return action_result.set_status(phantom.APP_SUCCESS)
    
    def _handle_update_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]
        severity = param.get("severity")
        status = param.get("status")
        title = param.get("title")
        description = param.get("description")
        owner_upn = param.get("owner_upn")
        classification = param.get("classification")
        classification_comment = param.get("classification_comment")
        classification_reason = param.get("classification_reason")

        # First, we have to retrieve the incident and then update the fields and PUT it back
        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}/{incident_name}"

        ret_val, incident = self._make_sentinel_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_UPDATE_INCIDENT)
            return action_result.get_status()

        updated_incident_base = {
            "properties": {
                "title": incident["properties"]["title"],
                "severity": incident["properties"]["severity"],
                "status": incident["properties"]["status"]
            }
        }

        if status:
            updated_incident_base["properties"]["status"] = status
        if severity:
            updated_incident_base["properties"]["severity"] = severity
        if title:
            updated_incident_base["properties"]["title"] = title
        if description:
            updated_incident_base["properties"]["description"] = description
        if owner_upn:
            updated_incident_base["properties"]["owner"] = {}
            updated_incident_base["properties"]["owner"]["userPrincipalName"] = owner_upn

        if status == "Closed":
            if classification:
                updated_incident_base["properties"]["classification"] = classification
            if classification_comment:
                updated_incident_base["properties"]["classificationComment"] = classification_comment
            if classification_reason:
                updated_incident_base["properties"]["classificationReason"] = classification_reason
    
        
        ret_val, updated_incident = self._make_sentinel_call(endpoint, action_result, method="put", json=updated_incident_base)
        
        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENT)
            return action_result.get_status()
 
        action_result.add_data(updated_incident)


        summary = action_result.update_summary({})
        summary["incident_id"] = updated_incident["id"]
        summary["incident_name"] = updated_incident["name"]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_incident_comment(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]
        message = param["message"]

        comment_id = int(datetime.utcnow().timestamp())

        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}/{incident_name}/comments/{comment_id}"

        payload = {
            "properties": {
                "message": message
            }
        }

        ret_val, response = self._make_sentinel_call(endpoint, action_result, method="put", json=payload)

        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_CREATING_INCIDENT_COMMENT)
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        query = param["query"]

        payload = {
            "query": query
        }

        ret_val, response = self._make_loganalytics_query(action_result, method="post", json=payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rows = []
        for row in response["tables"][0]["rows"]:
            row_data = {}
            for i, entry in enumerate(row):
                col_name = response["tables"][0]["columns"][i]["name"]
                col_value = entry
                row_data[col_name] = col_value
            rows.append(row_data)

        for row in rows:
            action_result.add_data(row)
    
        return action_result.set_status(phantom.APP_SUCCESS)


    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_asset_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "list_incidents":
            ret_val = self._handle_list_incidents(param)
        elif action_id == "get_incident":
            ret_val = self._handle_get_incident(param)
        elif action_id == "update_incident":
            ret_val = self._handle_update_incident(param)
        elif action_id == "get_incident_alerts":
            ret_val = self._handle_get_incident_alerts(param)
        elif action_id == "get_incident_entities":
            ret_val = self._handle_get_incident_entities(param)
        elif action_id == "add_incident_comment":
            ret_val = self._handle_add_incident_comment(param)
        elif action_id == "run_query":
            ret_val = self._handle_run_query(param)
        elif action_id == "on_poll":
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._tenant_id = config["tenant_id"]
        self._subscription_id = config["subscription_id"]
        self._resource_group_name = config["resource_group_name"]
        self._workspace_name = config["workspace_name"]
        self._workspace_id = config["workspace_id"]
        self._client_id = config["client_id"]
        self._client_secret = config["client_secret"]

        self._login_url = SENTINEL_LOGIN_URL.format(tenant_id=self._tenant_id)
        self._loganalytics_login_url = LOGANALYTICS_LOGIN_URL.format(tenant_id=self._tenant_id)
         
        self._api_url = SENTINEL_API_URL.format(subscription_id=self._subscription_id, resource_group=self._resource_group_name, workspace_name=self._workspace_name)
        self._loganalytics_api_url = LOGANALYTICS_API_URL.format(workspace_id=self._workspace_id)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _generate_new_access_token(self, action_result):
        """ This function is used to generate new access token using the code obtained on authorization.
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        login_payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": SENTINEL_LOGIN_SCOPE,
            "grant_type": "client_credentials"
        }

        ret_val, resp_json = self._make_rest_call(self._login_url,
            action_result=action_result,
            method="post",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=login_payload
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[STATE_TOKEN_KEY] = resp_json[SENTINEL_JSON_ACCESS_TOKEN]
        self.save_state(self._state)
        self.load_state()

        return phantom.APP_SUCCESS
    
    def _generate_new_loganalytics_access_token(self, action_result):
        login_payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "resource": LOGANALYTICS_LOGIN_RESOURCE,
            "grant_type": "client_credentials"
        }

        ret_val, resp_json = self._make_rest_call(self._loganalytics_login_url,
            action_result=action_result,
            method="post",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=login_payload
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[STATE_LOGANALYTICS_TOKEN_KEY] = resp_json[SENTINEL_JSON_ACCESS_TOKEN]
        self.save_state(self._state)
        self.load_state()

        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SentinelConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SentinelConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
