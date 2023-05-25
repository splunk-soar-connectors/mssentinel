# File: request_handler.py
#
# Copyright (c) None Splunk Inc.
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

import grp
import json
import os
import pathlib
import pwd

import encryption_helper
from django.http import HttpResponse

import mssentinel_consts as consts


def handle_request(request, path_parts):
    return SentinelRequestHandler(request, path_parts).handle_request()


class SentinelRequestHandler:

    def __init__(self, request, path_parts):
        """
        :param request: Data given to REST endpoint
        :param path_parts: parts of the URL passed
        """
        self.request = request
        self.path_parts = path_parts
        self.rsh = RequestUtilHandler()

    def handle_request(self):

        if len(self.path_parts) < 2:
            return HttpResponse('error: True, message: Invalid REST endpoint request', content_type="text/plain",
                                status=consts.MS_SENTINEL_BAD_REQUEST_CODE)

        call_type = self.path_parts[1]

        # To handle authorize request in test connectivity action
        if call_type == 'start_oauth':
            return self._handle_login_redirect('admin_consent_url')

        # To handle response from microsoft login page
        if call_type == 'result':
            return_val = self._handle_login_response()
            asset_id = self.request.GET.get('state')
            if asset_id:
                if not self.rsh.is_valid_asset_id(asset_id):
                    return HttpResponse("Error: Invalid asset_id", content_type="text/plain",
                                        status=consts.MS_SENTINEL_BAD_REQUEST_CODE)
                auth_status_file_path = self.rsh.get_file_path(asset_id, is_state_file=False)
                auth_status_file_path.touch(mode=664, exist_ok=True)
                try:
                    uid = pwd.getpwnam('apache').pw_uid
                    gid = grp.getgrnam('phantom').gr_gid
                    os.chown(auth_status_file_path, uid, gid)
                    # nosemgrep file traversal risk is handled by blocking non-alphanum strings
                except Exception:
                    pass

            return return_val
        return HttpResponse('error: Invalid endpoint', content_type="text/plain",
                            status=consts.MS_SENTINEL_NOT_FOUND_CODE)

    def _handle_login_redirect(self, key):
        """ This function is used to redirect login request to microsoft login page.

        :param key: Key to search in state file
        :return: response authorization_url/admin_consent_url
        """

        asset_id = self.request.GET.get('asset_id')
        if not asset_id:
            return HttpResponse('ERROR: Asset ID not found in URL', content_type="text/plain",
                                status=consts.MS_SENTINEL_BAD_REQUEST_CODE)
        state = self.rsh.load_app_state(asset_id)
        if not state:
            return HttpResponse('ERROR: Invalid asset_id', content_type="text/plain",
                                status=consts.MS_SENTINEL_BAD_REQUEST_CODE)
        url = state.get(key)
        if not url:
            return HttpResponse(f'App state is invalid, {key} not found.', content_type="text/plain",
                                status=consts.MS_SENTINEL_BAD_REQUEST_CODE)
        response = HttpResponse(status=302)
        response['Location'] = url
        return response

    def _handle_login_response(self):
        """ This function is used to get the login response of authorization request from microsoft login page.

        :return: HttpResponse. The response displayed on authorization URL page
        """

        asset_id = self.request.GET.get('state')
        if not asset_id:
            return HttpResponse(f'ERROR: Asset ID not found in URL\n{json.dumps(self.request.GET)}',
                                content_type="text/plain", status=consts.MS_SENTINEL_BAD_REQUEST_CODE)

        # Check for error in URL
        error = self.request.GET.get('error')
        error_description = self.request.GET.get('error_description')

        # If there is an error in response
        if error:
            message = f'Error: {error}'
            if error_description:
                message = f'{message} Details: {error_description}'
            return HttpResponse(f'Server returned {message}', content_type="text/plain",
                                status=consts.MS_SENTINEL_BAD_REQUEST_CODE)

        code = self.request.GET.get('code')

        # If code is not available
        if not code:
            return HttpResponse(f'Error while authenticating\n{json.dumps(self.request.GET)}',
                                content_type="text/plain", status=consts.MS_SENTINEL_BAD_REQUEST_CODE)

        state = self.rsh.load_app_state(asset_id)

        # If value of admin_consent is not available, value of code is available
        state['code'] = code
        self.rsh.save_app_state(state, asset_id, None)

        return HttpResponse('Code received. Please close this window, the action will continue to get new token.',
                            content_type="text/plain")


class RequestUtilHandler:

    def __init__(self):
        pass

    @staticmethod
    def get_file_path(asset_id, is_state_file=True):
        """ This function gets the path of the auth status file of an asset id.

        :param asset_id: asset_id
        :param is_state_file: boolean parameter for state file
        :return: file_path: Path object of the file
        """
        current_file_path = pathlib.Path(__file__).resolve()
        if is_state_file:
            input_file = f'{asset_id}_state.json'
        else:
            input_file = f'{asset_id}_oauth_task.out'
        output_file_path = current_file_path.with_name(input_file)
        return output_file_path

    @staticmethod
    def is_valid_asset_id(asset_id):
        """ This function validates an asset id.
        Must be an alphanumeric string of less than 128 characters.

        :param asset_id: asset_id
        :return: is_valid: Boolean True if valid, False if not.
        """
        if isinstance(asset_id, str) and asset_id.isalnum() and len(asset_id) <= 128:
            return True
        return False

    @staticmethod
    def encrypt_state(state, salt):
        """
        Encrypts the state.
        :param state: state dictionary
        :param salt: salt used for encryption
        :return: encrypted state
        """

        access_token = state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_ACCESS_TOKEN_STRING)
        if access_token:
            state[consts.MS_SENTINEL_TOKEN_STRING][consts.MS_SENTINEL_ACCESS_TOKEN_STRING] = \
                encryption_helper.encrypt(access_token, salt)

        refresh_token = state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_REFRESH_TOKEN_STRING)
        if refresh_token:
            state[consts.MS_SENTINEL_TOKEN_STRING][consts.MS_SENTINEL_REFRESH_TOKEN_STRING] = \
                encryption_helper.encrypt(refresh_token, salt)

        loganalytic_token = state.get(consts.MS_SENTINEL_LOGANALYTICS_TOKEN_KEY)
        if loganalytic_token:
            state[consts.MS_SENTINEL_LOGANALYTICS_TOKEN_KEY] = encryption_helper.encrypt(loganalytic_token, salt)

        code = state.get("code")
        if code:
            state["code"] = encryption_helper.encrypt(code, salt)

        state["is_encrypted"] = True

        return state

    @staticmethod
    def decrypt_state(state, salt):
        """
        Decrypts the state.
        :param state: state dictionary
        :param salt: salt used for decryption
        :return: decrypted state
        """

        if not state.get("is_encrypted"):
            return state

        access_token = state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_ACCESS_TOKEN_STRING)
        if access_token:
            state[consts.MS_SENTINEL_TOKEN_STRING][consts.MS_SENTINEL_ACCESS_TOKEN_STRING] = \
                encryption_helper.decrypt(access_token, salt)

        refresh_token = state.get(consts.MS_SENTINEL_TOKEN_STRING, {}).get(consts.MS_SENTINEL_REFRESH_TOKEN_STRING)
        if refresh_token:
            state[consts.MS_SENTINEL_TOKEN_STRING][consts.MS_SENTINEL_REFRESH_TOKEN_STRING] = \
                encryption_helper.decrypt(refresh_token, salt)

        loganalytic_token = state.get(consts.MS_SENTINEL_LOGANALYTICS_TOKEN_KEY)
        if loganalytic_token:
            state[consts.MS_SENTINEL_LOGANALYTICS_TOKEN_KEY] = encryption_helper.decrypt(loganalytic_token, salt)

        code = state.get("code")
        if code:
            state["code"] = encryption_helper.decrypt(code, salt)

        return state

    def load_app_state(self, asset_id, app_connector=None):
        """ This function is used to load the current state file.

        :param asset_id: asset_id
        :param app_connector: Object of app_connector class
        :return: state: Current state file as a dictionary
        """

        asset_id = str(asset_id)
        if not self.is_valid_asset_id(asset_id):
            if app_connector:
                app_connector.debug_print('In _load_app_state: Invalid asset_id')
            return {}

        state_file_path = self.get_file_path(asset_id)

        state = {}
        try:
            with open(state_file_path, 'r') as state_file:
                state = json.load(state_file)
        except Exception as e:
            if app_connector:
                app_connector.error_print(f'In _load_app_state: Exception: {str(e)}')

        if app_connector:
            app_connector.debug_print('Loaded state: ', state)

        try:
            state = self.decrypt_state(state, asset_id)
        except Exception as e:
            if app_connector:
                app_connector.error_print("{}: {}".format("Error", str(e)))
            state = {}

        return state

    def save_app_state(self, state, asset_id, app_connector):
        """ This function is used to save current state in file.

        :param state: Dictionary which contains data to write in state file
        :param asset_id: asset_id
        :param app_connector: Object of app_connector class
        :return: status: True/False
        """
        asset_id = str(asset_id)
        if not self.is_valid_asset_id(asset_id):
            if app_connector:
                app_connector.debug_print('In _save_app_state: Invalid asset_id')
            return {}

        state_file_path = self.get_file_path(asset_id)

        try:
            state = self.encrypt_state(state, asset_id)
        except Exception as e:
            if app_connector:
                app_connector.error_print("{}: {}".format("Error", str(e)))
            return False

        if app_connector:
            app_connector.debug_print('Saving state: ', state)

        try:
            with open(state_file_path, 'w+') as state_file:
                json.dump(state, state_file)
        except Exception as e:
            if app_connector:
                app_connector.error_print(f'Unable to save state file: {str(e)}')

        return True
