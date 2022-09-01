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

# Usage of the consts file is recommended
# from sentinel_consts import *

import requests
import json
from bs4 import BeautifulSoup

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
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
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

            if r.status_code == 401:
                ret_val = self._generate_new_access_token(action_result)
                if phantom.is_fail(ret_val):
                    return action_result.get_status(), None
                access_token = self._state[STATE_TOKEN_KEY]
                kwargs["headers"]["Authorization"] = f"Bearer {access_token}"

                r = request_func(
                    endpoint,
                    verify=verify,
                    **kwargs
                )

        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)
    
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

        return self._make_rest_call(endpoint, action_result, method, **kwargs)

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

            # TODO: Error Handling            
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

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        #return action_result.set_status(phantom.APP_ERROR, "Not implemented yet")

        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        config = self.get_config()

        start_time_scheduled_poll = config.get(SENTINEL_APP_CONFIG_START_TIME_SCHEDULED_POLL)
        last_modified_time = (datetime.now() - timedelta(days=7)).strftime(SENTINEL_APP_DT_STR_FORMAT) # Let's fall back to the last 7 days
        incidents = []


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
            max_incidents = int(config.get(SENTINEL_APP_CONFIG_FIRST_RUN_MAX_INCIDENTS, 1000))
        else:
            if self._state.get(STATE_LAST_TIME):
                last_modified_time = self._state[STATE_LAST_TIME]


        endpoint = f"{self._api_url}{SENTINEL_API_INCIDENTS}"
    
        filter = f"(properties/lastModifiedTimeUtc ge {last_modified_time})"

        params = {
            "$filter": filter,
            "$top": SENTINEL_API_INCIDENTS_PAGE_SIZE
        }

        ret_val, incident_list = self._make_paginated_sentinel_call(endpoint, action_result, params, max_incidents)
        if phantom.is_fail(ret_val):
            self.save_progress(LOG_FAILED_RETRIEVING_INCIDENTS)
            return action_result.get_status()

        # TODO: Create / Update containers appropriately
        #  https://github.com/splunk-soar-connectors/msgraphsecurityapi/blob/PAPP-5080-initial-release/microsoftgraphsecurityapi_connector.py


        for incident in incident_list:
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary["total_incidents"] = len(incident_list)
        summary["filter"] = filter
        summary["first_run"] = self._state.get(STATE_FIRST_RUN, True)

        if incidents:
            if SENTINEL_JSON_LAST_MODIFIED not in incidents[0]:
                return action_result.set_status(phantom.APP_ERROR, LOG_NO_LAST_MODIFIED_TIME)

            self._state[STATE_LAST_TIME] = incidents[0][SENTINEL_JSON_LAST_MODIFIED]
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
        self._client_id = config["client_id"]
        self._client_secret = config["client_secret"]

        self._login_url = SENTINEL_LOGIN_URL.format(tenant_id=self._tenant_id)
        self._api_url = SENTINEL_API_URL.format(subscription_id=self._subscription_id, resource_group=self._resource_group_name, workspace_name=self._workspace_name)

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

        ret_val, resp_json = self._make_rest_call(self._login_url, action_result=action_result, data=login_payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[STATE_TOKEN_KEY] = resp_json[SENTINEL_JSON_ACCESS_TOKEN]
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
