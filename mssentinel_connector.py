# File: mssentinel_connector.py
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

from __future__ import print_function, unicode_literals

import json
import time
from datetime import datetime, timedelta
from urllib.parse import quote, urljoin, urlparse

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import mssentinel_consts as consts
from request_handler import RequestUtilHandler


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SentinelConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SentinelConnector, self).__init__()

        self._state = None
        self._asset_id = None
        self._tenant_id = None
        self._subscription_id = None
        self._client_id = None
        self._client_secret = None
        self._workspace_name = None
        self._workspace_id = None
        self._resource_group_name = None
        self._login_url = None
        self._loganalytics_login_url = None
        self._loganalytics_api_url = None
        self._api_url = None
        self._non_interactive = None
        self._access_token = None
        self._refresh_token = None
        self._loganalytic_token = None
        self._rsh = None

    def load_state(self):
        """
        Load the contents of the state file to the state dictionary and decrypt it.
        :return: loaded state
        """
        state = super().load_state()
        if not isinstance(state, dict):
            self.debug_print("Reseting the state file with the default format")
            state = {"app_version": self.get_app_json().get("app_version")}
            return state
        try:
            state = self._rsh.decrypt_state(state, self._asset_id)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.error_print("{}: {}".format("Decryption error", error_message))
            state = None
        return state

    def save_state(self, state):
        """
        Encrypt and save the current state dictionary to the state file.
        :param state: state dictionary
        :return: status
        """
        try:
            state = self._rsh.encrypt_state(state, self._asset_id)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.error_print("{}: {}".format("Encryption Error", error_message))

        return super().save_state(state)

    @staticmethod
    def _validate_integer(action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return RetVal(action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_VALID_INT_MESSAGE.format(param=key)))

                parameter = int(parameter)
            except Exception:
                return RetVal(action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_VALID_INT_MESSAGE.format(param=key)))

            if parameter < 0:
                return RetVal(action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_NON_NEG_INT_MESSAGE.format(param=key)))
            if not allow_zero and parameter == 0:
                return RetVal(action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_NON_NEG_NON_ZERO_INT_MESSAGE.format(param=key)))

        return RetVal(phantom.APP_SUCCESS, parameter)

    @staticmethod
    def _get_dir_name_from_app_name(app_name):
        """Get name of the directory for the app.

        :param app_name: Name of the application for which directory name is required
        :return: app_name: Name of the directory for the application
        """

        app_name = "".join([x for x in app_name if x.isalnum()])
        app_name = app_name.lower()
        if not app_name:
            app_name = "app_for_phantom"
        return app_name

    def _get_asset_name(self, action_result):
        """Get name of the asset using SOAR URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        url = urljoin(self.get_phantom_base_url(), f"rest/asset/{self._asset_id}")
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)  # nosemgrep

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get("name")
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, f"Asset Name for id: {self._asset_id} not found."), None
        return phantom.APP_SUCCESS, asset_name

    def _get_external_phantom_base_url(self, action_result):
        """Get base url of SOAR.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of SOAR
        """

        url = urljoin(self.get_phantom_base_url(), "rest/system_info")
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)  # nosemgrep
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get("base_url").rstrip("/")
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_BASE_URL_NOT_FOUND_MESSAGE), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_external_phantom_base_url(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress(f"Using SOAR base URL: {phantom_base_url}")
        app_json = self.get_app_json()
        app_id = app_json["appid"]
        app_name = app_json["name"]

        app_dir_name = self._get_dir_name_from_app_name(app_name)
        url_to_app_rest = f"{phantom_base_url}/rest/handler/{app_dir_name}_{app_id}/{asset_name}"
        return phantom.APP_SUCCESS, url_to_app_rest

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_message = consts.MS_SENTINEL_ERROR_MESSAGE_UNKNOWN

        self.error_print("Exception occurred.", dump_object=e)
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception:
            self.error_print("Exception occurred while getting error code and message")

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_message)

        return error_text

    @staticmethod
    def _process_empty_response(response, action_result):
        if response.status_code in consts.MS_SENTINEL_EMPTY_RESPONSE_CODES:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header," " Status Code: {}".format(response.status_code)
            ),
            None,
        )

    @staticmethod
    def _check_invalid_since_utc_time(time_format):
        """Determine that given time is not before 1970-01-01T00:00:00Z.
        Parameters:
            :param time_format: object of time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Check that given time must not be before 1970-01-01T00:00:00Z.
        if time_format < datetime.strptime("1970-01-01T00:00:00Z", consts.DATE_STR_FORMAT):
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
        try:
            # Check for the time is in valid format or not
            curr_time = datetime.strptime(date, consts.DATE_STR_FORMAT)
            # Taking current UTC time as end time
            end_time = datetime.utcnow()
            # Check for given time is not before 1970-01-01T00:00:00Z
            ret_val = self._check_invalid_since_utc_time(curr_time)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_UTC_SINCE_TIME_ERROR)
            # Checking future date
            if curr_time >= end_time:
                message = consts.MS_SENTINEL_GREATER_EQUAL_TIME_ERROR.format(consts.MS_SENTINEL_CONFIG_TIME_POLL_NOW)
                return action_result.set_status(phantom.APP_ERROR, message)
        except Exception as e:
            message = consts.MS_SENTINEL_INVALID_DATE_FORMAT.format(self._get_error_message_from_exception(e))
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    @staticmethod
    def _process_html_response(response, action_result):
        # A html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Error from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_txt = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(error_txt))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Response from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Error from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", verify=True, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        try:
            r = request_func(endpoint, verify=verify, **kwargs)
        except Exception as e:
            error_txt = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(error_txt))), resp_json
            )

        return self._process_response(r, action_result)

    def _make_loganalytics_query(self, action_result, method="post", **kwargs):
        endpoint = f"{self._loganalytics_api_url}"

        if "headers" not in kwargs:
            kwargs["headers"] = {}

        if "timeout" not in kwargs:
            kwargs["timeout"] = consts.MS_SENTINEL_DEFAULT_TIMEOUT

        if not self._loganalytic_token:
            ret_val = self._generate_new_loganalytics_access_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        kwargs["headers"]["Authorization"] = f"Bearer {self._loganalytic_token}"
        ret_val, resp_json = self._make_rest_call(endpoint, action_result, method, **kwargs)

        message = action_result.get_message()
        if message and any(failure_message in message for failure_message in consts.MS_SENTINEL_TOKEN_EXPIRED_MESSAGE):
            self.debug_print("Token is invalid/expired. Hence, generating a new token.")
            ret_val = self._generate_new_loganalytics_access_token(action_result=action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            kwargs["headers"]["Authorization"] = f"Bearer {self._loganalytic_token}"
            return self._make_rest_call(endpoint, action_result, method, **kwargs)

        return ret_val, resp_json

    def _make_sentinel_call(self, endpoint, action_result, method="get", **kwargs):

        if "params" not in kwargs:
            kwargs["params"] = {}

        if "timeout" not in kwargs:
            kwargs["timeout"] = consts.MS_SENTINEL_DEFAULT_TIMEOUT

        parsed_endpoint = urlparse(endpoint)
        if "api-version" not in parsed_endpoint.query:
            kwargs["params"]["api-version"] = consts.MS_SENTINEL_API_VERSION

        if "headers" not in kwargs:
            kwargs["headers"] = {}
        self.debug_print("Token che ke?: {}".format(self._access_token))
        if not self._access_token:
            self.debug_print("No Token")
            status = self._generate_new_access_token(action_result)
            if phantom.is_fail(status):
                return action_result.get_status(), None

        kwargs["headers"]["Authorization"] = f"Bearer {self._access_token}"

        ret_val, resp_json = self._make_rest_call(endpoint, action_result, method, **kwargs)

        # If token is expired, generate a new token
        message = action_result.get_message()
        if message and any(failure_message in message for failure_message in consts.MS_SENTINEL_TOKEN_EXPIRED_MESSAGE):
            self.debug_print("Token is invalid/expired. Hence, generating a new token.")
            ret_val = self._generate_new_access_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            kwargs["headers"]["Authorization"] = f"Bearer {self._access_token}"
            return self._make_rest_call(endpoint, action_result, method, **kwargs)

        return ret_val, resp_json

    def _make_paginated_sentinel_call(self, endpoint, action_result, params, limit):

        results_list = []
        next_link = ""
        while True:
            if next_link:
                endpoint = next_link
                params = {}

            ret_val, res_json = self._make_sentinel_call(endpoint, action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            if consts.MS_SENTINEL_JSON_VALUE not in res_json:
                return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_FAILED_RETRIEVING_INCIDENTS), None

            [results_list.append(entry) for entry in res_json[consts.MS_SENTINEL_JSON_VALUE]]

            if limit <= len(results_list):
                results_list = results_list[:limit]
                break

            if not res_json.get(consts.MS_SENTINEL_JSON_NEXT_LINK):
                break

            next_link = res_json[consts.MS_SENTINEL_JSON_NEXT_LINK]

        return phantom.APP_SUCCESS, results_list

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))
        app_state = {}
        if not self._non_interactive:
            self.save_progress("Getting App REST endpoint URL")
            # Get the URL to the app's REST Endpoint, this is the url that the TC dialog
            # box will ask the user to connect to
            ret_val, app_rest_url = self._get_app_rest_url(action_result)

            if phantom.is_fail(ret_val):
                self.save_progress(consts.MS_REST_URL_NOT_AVAILABLE_MESSAGE.format(error=self.get_status()))
                return self.set_status(phantom.APP_ERROR)

            # Append /result to create redirect_uri
            redirect_uri = "{0}/result".format(app_rest_url)
            app_state["redirect_uri"] = redirect_uri

            self.save_progress(consts.MS_OAUTH_URL_MESSAGE)
            self.save_progress(redirect_uri)

            self._client_id = quote(self._client_id)
            self._tenant_id = quote(self._tenant_id)

            query_params = {
                "client_id": self._client_id,
                "state": self._asset_id,
                "response_type": "code",
                "scope": consts.MS_SENTINEL_CODE_GENERATION_SCOPE,
                "redirect_uri": redirect_uri,
            }
            authorization_url = consts.MS_SENTINEL_AUTHORIZE_URL.format(tenant_id=self._tenant_id)
            query_string = "&".join(f"{key}={value}" for key, value in query_params.items())

            authorization_url = f"{authorization_url}?{query_string}"

            app_state["admin_consent_url"] = authorization_url

            # The URL that the user should open in a different tab.
            # This is pointing to a REST endpoint that points to the app
            url_to_show = f"{app_rest_url}/start_oauth?asset_id={self._asset_id}&"

            # Save the state, will be used by the request handler
            self._rsh.save_app_state(app_state, self._asset_id, self)

            self.save_progress(consts.MS_SENTINEL_CONNECTIVITY_PROCESS)
            self.save_progress(url_to_show)
            self.save_progress(consts.MS_SENTINEL_AUTHORIZE_TROUBLESHOOT_MESSAGE)

            time.sleep(consts.MS_SENTINEL_WAIT_TIME)

            completed = False

            if not self._rsh.is_valid_asset_id(self._asset_id):
                return action_result.set_status(phantom.APP_ERROR, "Invalid asset id")

            auth_status_file_path = self._rsh.get_file_path(self._asset_id, is_state_file=False)

            self.save_progress("Waiting for authorization to complete")

            for i in range(0, 40):

                self.send_progress("{0}".format("." * (i % 10)))

                if auth_status_file_path.is_file():
                    completed = True
                    auth_status_file_path.unlink()
                    break

                time.sleep(consts.MS_TC_STATUS_SLEEP)

            if not completed:
                self.save_progress("Authentication process does not seem to be completed. Timing out")
                self.save_progress(consts.MS_SENTINEL_TEST_CONNECTIVITY_FAILED)
                return self.set_status(phantom.APP_ERROR)

            # Load the state again, since the http request handlers would have saved the result of the admin consent
            self._state = self._rsh.load_app_state(self._asset_id, self)
            if not self._state:
                self.save_progress(consts.MS_STATE_FILE_ERROR_MESSAGE)
                self.save_progress(consts.MS_SENTINEL_TEST_CONNECTIVITY_FAILED)
                return action_result.set_status(phantom.APP_ERROR)

            if not self._state.get("code"):
                self.save_progress(consts.MS_AUTHORIZATION_ERROR_MESSAGE)
                self.save_progress(consts.MS_SENTINEL_TEST_CONNECTIVITY_FAILED)
                return action_result.set_status(phantom.APP_ERROR)

            self.send_progress("")

        self.save_progress(consts.MS_SENTINEL_RETRIEVING_ACCESS_TOKEN_MESSAGE)

        ret_val = self._generate_new_access_token(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress(consts.MS_SENTINEL_FAILED_RETRIEVING_ACCESS_TOKEN)
            self.save_progress(consts.MS_SENTINEL_TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()
        if not self._non_interactive:
            state_file_path = self._rsh.get_file_path(self._asset_id)
            state_file_path.unlink()
        self.save_progress(consts.MS_SENTINEL_SUCCESS_RETRIEVING_ACCESS_TOKEN)

        self.save_progress("Getting incident details")
        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}"
        ret_val, resp_json = self._make_sentinel_call(endpoint, action_result, params={"$top": 1})

        if phantom.is_fail(ret_val):
            self.save_progress(consts.MS_SENTINEL_FAILED_RETRIEVING_INCIDENT)
            self.save_progress(consts.MS_SENTINEL_TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()
        self.save_progress(consts.MS_SENTINEL_TEST_CONNECTIVITY_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self, param):
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        limit = consts.MAX_INCIDENTS_DEFAULT
        if param.get("limit"):
            ret_val, limit = self._validate_integer(action_result, param.get("limit"), "limit")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        filter = param.get("filter")
        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}"

        params = {"$top": min(limit, consts.MS_SENTINEL_DEFAULT_SIZE)}

        if filter:
            params["$filter"] = filter

        ret_val, incident_list = self._make_paginated_sentinel_call(endpoint, action_result, params, limit)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        [action_result.add_data(incident) for incident in incident_list]

        summary = action_result.update_summary({})
        summary["total_incidents"] = len(incident_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_artifacts(self, incident):
        """Ingest artifact into the new or existing container.
        Parameters:
            :param incident: incident to ingest as an artifact
        Returns:
            :return: None
        """
        container = {
            "name": incident["properties"]["title"],
            "description": "incident ingested using MS Sentinel API",
            "source_data_identifier": incident["name"],
        }
        ret_val, message, container_id = self.save_container(container)

        if phantom.is_fail(ret_val):
            self.debug_print(consts.MS_SENTINEL_CONTAINER_ERROR_MESSAGE.format(container_id, message))

        if consts.MS_SENTINEL_DUPLICATE_CONTAINER_MESSAGE in message:
            self.debug_print(consts.MS_SENTINEL_DUPLICATE_CONTAINER_MESSAGE)

        artifact = [
            {
                "label": "incident",
                "name": "incident Artifact",
                "source_data_identifier": incident.get("name"),
                "cef": incident,
                "container_id": container_id,
                "run_automation": True,
            }
        ]
        ret_val, message, _ = self.save_artifacts(artifact)
        if phantom.is_fail(ret_val):
            self.debug_print(consts.MS_SENTINEL_ARTIFACT_ERROR_MESSAGE.format(message))

    def _validate_on_poll_config_param(self, action_result, config):
        start_time_scheduled_poll = config.get(consts.START_TIME_SCHEDULED_POLL)
        if start_time_scheduled_poll:
            ret_val = self._check_date_format(action_result, start_time_scheduled_poll)
            if phantom.is_fail(ret_val):
                self.debug_print(action_result.get_message())
                return action_result.get_status(), None, None
            last_modified_time = start_time_scheduled_poll
        else:
            last_modified_time = (datetime.now() - timedelta(days=7)).strftime(consts.DATE_STR_FORMAT)  # Let's fall back to the last 7 days
        return phantom.APP_SUCCESS, consts.MAX_INCIDENTS_DEFAULT, last_modified_time

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        config = self.get_config()

        ret_val, max_incidents, last_modified_time = self._validate_on_poll_config_param(action_result, config)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not self._access_token:
            ret_val = self._generate_new_access_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        if self.is_poll_now():
            max_incidents = param[phantom.APP_JSON_CONTAINER_COUNT]
        elif self._state.get(consts.STATE_FIRST_RUN, True):
            self._state[consts.STATE_FIRST_RUN] = False
            ret_val, max_incidents = self._validate_integer(
                action_result, config.get(consts.FIRST_RUN_MAX_INCIDENTS, max_incidents), consts.FIRST_RUN_MAX_INCIDENTS
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        else:
            last_modified_time = self._state.get(consts.STATE_LAST_TIME, last_modified_time)

        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}"

        params = {
            "$filter": f"(properties/lastModifiedTimeUtc gt {last_modified_time})",
            "$top": consts.MS_SENTINEL_DEFAULT_SIZE,
            "$orderby": "properties/createdTimeUtc",
        }

        ret_val, incidents = self._make_paginated_sentinel_call(endpoint, action_result, params, max_incidents)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(f"Successfully fetched {len(incidents)} incidents.")

        # Ingest the incidents
        for incident in incidents:
            # Save artifacts for incidents
            try:
                self._save_artifacts(incident)
            except Exception as e:
                message = self._get_error_message_from_exception(e)
                self.debug_print("Error occurred while saving artifacts for incidents. Error: {}".format(message))

        if incidents and not self.is_poll_now():
            if consts.MS_SENTINEL_JSON_LAST_MODIFIED not in incidents[-1]["properties"]:
                return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_NO_LAST_MODIFIED_TIME)

            self._state[consts.STATE_LAST_TIME] = incidents[-1]["properties"][consts.MS_SENTINEL_JSON_LAST_MODIFIED]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident_alerts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]

        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}/" f"{incident_name}{consts.MS_SENTINEL_API_INCIDENTS_ALERTS}"

        ret_val, alerts_response = self._make_sentinel_call(endpoint, action_result, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress(consts.MS_SENTINEL_FAILED_RETRIEVING_INCIDENT_ALERTS)
            return action_result.get_status()

        [action_result.add_data(alert) for alert in alerts_response[consts.MS_SENTINEL_JSON_VALUE]]

        summary = action_result.update_summary({})
        summary["total_alerts"] = len(alerts_response["value"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident_entities(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]

        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}/" f"{incident_name}{consts.MS_SENTINEL_API_INCIDENTS_ENTITIES}"

        ret_val, entities_response = self._make_sentinel_call(endpoint, action_result, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress(consts.MS_SENTINEL_FAILED_RETRIEVING_INCIDENT_ENTITIES)
            return action_result.get_status()

        action_result.add_data(entities_response)

        summary = action_result.update_summary({})
        summary["total_entities"] = len(entities_response["entities"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]

        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}/{incident_name}"

        ret_val, incident = self._make_sentinel_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(consts.MS_SENTINEL_FAILED_RETRIEVING_INCIDENT)
            return action_result.get_status()

        action_result.add_data(incident)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved incident details")

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
        labels = None
        if param.get("labels"):
            labels = list(set(filter(None, [label.strip() for label in param.get("labels", "").split(",")])))
            if not labels:
                return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_VALID_LABEL_PARAM.format(param="labels"))
        params = [severity, status, title, description, owner_upn, labels]

        # First, we have to retrieve the incident and then update the fields and PUT it back
        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}/{incident_name}"

        ret_val, incident = self._make_sentinel_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(consts.MS_SENTINEL_FAILED_UPDATE_INCIDENT)
            return action_result.get_status()

        updated_incident_base = {
            "properties": {
                "title": incident["properties"]["title"],
                "severity": incident["properties"]["severity"],
                "status": incident["properties"]["status"],
                "owner": incident["properties"]["owner"],
                "labels": incident["properties"]["labels"],
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
        if labels:
            [updated_incident_base["properties"]["labels"].append({"labelName": val, "labelType": "User"}) for val in labels]

        # check if no parameter is provided
        if not any(params):
            return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_NO_PARAMETER_MESSAGE)

        if status == "Closed":
            if classification:
                updated_incident_base["properties"]["classification"] = classification
            if classification_comment:
                updated_incident_base["properties"]["classificationComment"] = classification_comment
            if classification_reason:
                updated_incident_base["properties"]["classificationReason"] = classification_reason

        ret_val, updated_incident = self._make_sentinel_call(endpoint, action_result, method="put", json=updated_incident_base)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(updated_incident)

        return action_result.set_status(phantom.APP_SUCCESS, "Incident updated successfully")

    def _handle_add_incident_comment(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        incident_name = param["incident_name"]
        message = param["message"]

        comment_id = int(datetime.utcnow().timestamp())

        endpoint = f"{self._api_url}{consts.MS_SENTINEL_API_INCIDENTS}/{incident_name}/comments/{comment_id}"

        payload = {"properties": {"message": message}}

        ret_val, response = self._make_sentinel_call(endpoint, action_result, method="put", json=payload)

        if phantom.is_fail(ret_val):
            self.debug_print(consts.MS_SENTINEL_FAILED_CREATING_INCIDENT_COMMENT)
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Comment added successfully")

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))

        query = param["query"]
        timespan = param.get("timespan")

        payload = {"query": query}

        if timespan:
            payload["timespan"] = timespan

        ret_val, response = self._make_loganalytics_query(action_result, method="post", json=payload)

        if phantom.is_fail(ret_val):
            self.debug_print(consts.MS_SENTINEL_FAILED_LOGANALYTICS_QUERY)
            return action_result.get_status()

        self.save_progress("Dataa: {}".format(response))

        for table in response["tables"]:
            table_name = table["name"]
            for row in table["rows"]:
                row_data = {"SentinelTableName": table_name}
                for i, col_value in enumerate(row):
                    col_name = table["columns"][i]["name"]
                    row_data[col_name] = col_value
                action_result.add_data(row_data)

        summary = action_result.update_summary({})
        summary["total_rows"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_asset_connectivity":
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
        self._asset_id = self.get_asset_id()
        self._rsh = RequestUtilHandler()
        self._state = self.load_state()

        if not self._state:
            self.save_progress(consts.MS_SENTINEL_STATE_FILE_CORRUPT_ERROR)
            self._state = {"app_version": self.get_app_json().get("app_version")}

        # get the asset config
        config = self.get_config()

        self._tenant_id = config["tenant_id"]
        self._subscription_id = config["subscription_id"]
        self._resource_group_name = config["resource_group_name"]
        self._workspace_name = config["workspace_name"]
        self._workspace_id = config["workspace_id"]
        self._client_id = config["client_id"]
        self._client_secret = config["client_secret"]

        self._login_url = consts.MS_SENTINEL_LOGIN_URL.format(tenant_id=self._tenant_id)
        self._loganalytics_login_url = consts.LOGANALYTICS_LOGIN_URL.format(tenant_id=self._tenant_id)

        self._api_url = consts.MS_SENTINEL_API_URL.format(
            subscription_id=self._subscription_id, resource_group=self._resource_group_name, workspace_name=self._workspace_name
        )
        self._loganalytics_api_url = consts.LOGANALYTICS_API_URL.format(workspace_id=self._workspace_id)
        self._non_interactive = config.get("non_interactive", False)
        self._access_token = self._state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_ACCESS_TOKEN_STRING)
        self._refresh_token = self._state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_REFRESH_TOKEN_STRING)
        self._loganalytic_token = self._state.get(consts.MS_SENTINEL_LOGANALYTICS_TOKEN_KEY)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _generate_new_access_token(self, action_result):
        """This function is used to generate new access token using the code obtained on authorization.
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        login_payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._non_interactive:
            login_payload["scope"] = consts.MS_SENTINEL_LOGIN_SCOPE
            login_payload["grant_type"] = "client_credentials"
        else:
            login_payload["redirect_uri"] = self._state.get("redirect_uri")
            auth_code = self._state.get("code", None)
            if self._state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_REFRESH_TOKEN_STRING, None):
                login_payload["refresh_token"] = self._refresh_token
                login_payload["grant_type"] = "refresh_token"
            elif auth_code:
                self._state.pop("code")
                login_payload["code"] = auth_code
                login_payload["grant_type"] = "authorization_code"
            else:
                return action_result.set_status(phantom.APP_ERROR, consts.MS_SENTINEL_STATE_FILE_ERROR)

        ret_val, resp_json = self._make_rest_call(
            self._login_url,
            action_result=action_result,
            method="post",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=login_payload,
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[consts.MS_SENTINEL_TOKEN_STRING] = resp_json
        self._access_token = resp_json.get(consts.MS_SENTINEL_ACCESS_TOKEN_STRING, None)
        self._refresh_token = resp_json.get(consts.MS_SENTINEL_REFRESH_TOKEN_STRING, None)

        return phantom.APP_SUCCESS

    def _generate_new_loganalytics_access_token(self, action_result):

        login_payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "resource": consts.LOGANALYTICS_LOGIN_RESOURCE,
            "grant_type": "client_credentials",
        }

        ret_val, resp_json = self._make_rest_call(
            self._loganalytics_login_url,
            action_result=action_result,
            method="post",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=login_payload,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._loganalytic_token = self._state[consts.MS_SENTINEL_LOGANALYTICS_TOKEN_KEY] = resp_json[consts.MS_SENTINEL_ACCESS_TOKEN_STRING]
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

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
            login_url = SentinelConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False, timeout=consts.MS_SENTINEL_DEFAULT_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers, timeout=consts.MS_SENTINEL_DEFAULT_TIMEOUT)
            session_id = r2.cookies["sessionid"]
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
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
