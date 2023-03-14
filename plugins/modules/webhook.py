#!/usr/bin/python
#
# Copyright (c) 2022, University of San Diego
# All Rights Reserved.
#
# Author: Kevin Keane
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Module for managing webhooks in Foreman/Satellite
This functionality is missing from the theforeman.foreman collection.
"""

# Framework Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

import json
import logging
import requests

from ansible.module_utils.basic import AnsibleModule, env_fallback

DOCUMENTATION = r'''
---
module: webhooks

short_description: Manages Webhooks

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: This module will create/update a Webhooks

options:
    name:
        description: This is name of the webhooks
        required: true
        type: str
    state:
        description: State of the entity
        Choices:
            - present (add the given host collections)
            - absent  (remove the given host collections)
    webhook_target_url:
        description: This is the target URL
        required: true
        type: str
    webhook_http_method:
        description: The HTTP method to use
        required: true
        type: str
        choices:
          - POST
          - GET
          - PUT
          - DELETE
          - PATCH
    webhook_http_content_type:
        description: This is the HTTP content type
        required: false
        default: application/json
        type: str
    webhook_event:
        description: The event that triggers the Webhook
        required: true
        type: str
    webhook_template:
        description: The template for this Webhook
        required: true
        type: str
    webhook_enabled:
        description: Whether this webhook is enabled or disabled.
        required: false
        default:  true
        type: bool
    webhook_verify_ssl:
        description: Whether this webhook will verify SSL or not
        required: false
        default:  true
        type: bool
    webhook_ssl_ca_certs:
        description: CA certs to validate against
        required: false
        type: str
    webhook_user:
        description: Username for authentication Webhook calls
        required: false
        type: str
    webhook_password:
        description: Password for authentication Webhook calls
        required: false
        type: str
        If specified, this module will not be idempotent
    webhook_http_headers:
        description: HTTP headers to include with Webhook calls
          Should be formatted as a JSON hash
        required: false
        type: str
    webhook_proxy_authorization:
        description: Whether this webhook should authorize with a proxy
        required: false
        type: bool
    server_url:
        description: |
          URL of the Foreman server.
          If the value is not specified in the task, the value of environment variable FOREMAN_SERVER_URL will be used instead.
        required: true
        type: str
    username:
        description: |
          Username accessing the Foreman server.
          If the value is not specified in the task, the value of environment variable FOREMAN_USERNAME will be used instead.
        required: true
        type: str
    password:
        description: |
            Password of the user accessing the Foreman server.
            If the value is not specified in the task, the value of environment variable FOREMAN_PASSWORD will be used instead.
        required: true
        type: str
    validate_certs:
        description: |
            Whether or not to verify the TLS certificates of the Foreman server.
            If the value is not specified in the task, the value of environment variable FOREMAN_VALIDATE_CERTS will be used instead.
        required: false
        default: true
        type: bool
        Choices:
            - false
            - true ← (default)

author:
    - Kevin Keane (@kkeane)
'''

EXAMPLES = r'''
# Add a host group
- name: Add a webhook call when building a host finished
  webhook:
    name: My webhook
    webhook_target_url: https://target.example.com/webhooks
    webhook_event: build_exited.event.foreman
    webhook_template: Post-build template
    server_url: foremanserver.example.com
    username: foreman_admin
    password: some_supersecure_password

Notes:
- If the template already exists, it must not be locked.

'''

RETURN = r'''
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
'''


class ApiAccess:
    """
    An object-oriented wrapper around the request
    module
    """

    def __init__(self, server_url, username, password, validate_certs):

        self._sat_session = requests.Session()
        self._sat_session.verify = validate_certs
        self._sat_session.auth = (username, password)
        self._server_url = server_url

    def get(self, location: str) -> tuple:
        """
        Performs a GET using the passed URL location
        """

        logging.debug("GET %s", location)
        result = self._sat_session.get(self._server_url + location)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json(), result.status_code

    def put(self, location: str, args) -> tuple:
        """
        Performs a PUT using the passed URL location
        """

        logging.debug("PUT %s", location)
        result = self._sat_session.put(self._server_url + location, json=args)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json(), result.status_code

    def post(self, location: str, args) -> tuple:
        """
        Performs a POST using the passed URL location
        """

        logging.debug("POST %s", location)
        result = self._sat_session.post(self._server_url + location, json=args)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json(), result.status_code

    def delete(self, location: str) -> tuple:
        """
        Performs a DELETE using the passed URL location
        """

        logging.debug("DELETE %s", location)
        result = self._sat_session.delete(self._server_url + location)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json(), result.status_code


def location_names_to_ids(input_set, all_locations):
    """
    Returns a set of IDs that match the location names in the
    input set

    input_set: a set of location titles.
    all_hcs: a list of all locations available in the system

    output: a set of location IDs. Any titles not found will be
            silently ignored.
    """
    # Note that we are iterating "backwards" over all available
    # locations, to find those that the caller requested.
    # A side effect is that we will not see any non-existent
    # locations.
    output_set = set()
    for loc in all_locations:
        if loc['title'] in input_set:
            output_set.add(loc['id'])
    return output_set


def location_list_to_ids(input_json):
    """
    Convert the list of locations as provided by the API
    to a set of IDs
    """
    output_set = set()
    for loc in input_json:
        output_set.add(loc['id'])
    return output_set


def organization_list_to_ids(input_str, all_organizations):
    """
    Retrieve the ID for an organization with the given name
    """

    output_set = set()
    for org in all_organizations:
        if org['name'] == input_str:
            output_set.add(org['id'])
    return output_set


def organization_ids_to_names(input_id, all_organizations):
    """
    Retrieve the ID for an organization with the given name
    Return value will be None if the organization does not
    exist.
    """

    for org in all_organizations:
        if org['id'] == input_id:
            return org['name']
    return None


def compare_set_field(updates, current, field, fieldname):
    """
    Check if the given field is provided, and set it if it is and
    if it is different from the current one
    Works for str, int, bool
    """

    if not field is None:
        if fieldname in current and field != current[fieldname]:
            updates[fieldname] = field


def run_module():
    """
    Run the module
    """

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        name=dict(type='str', required=True),
        description=dict(type='str', required=False),
        webhook_target_url=dict(type='str', required=True),
        webhook_http_method=dict(type='str',
                                 required=True,
                                 choices=['POST', 'GET', 'PUT', 'DELETE', 'PATCH']),
        webhook_http_content_type=dict(type='str', default='application/json'),
        webhook_event=dict(type='str', required=True),
        webhook_template=dict(type='str', required=True),
        webhook_enabled=dict(type='bool', default=True),
        webhook_verify_ssl=dict(type='bool', default=True),
        webhook_ssl_ca_certs=dict(type='str', required=False),
        webhook_user=dict(type='str', required=False),
        webhook_password=dict(type='str', no_log=True, required=False),
        webhook_http_headers=dict(type='str', required=False),
        webhook_proxy_authorization=dict(type='bool', default=False),
        state=dict(type='str',
                   required=False,
                   default='present',
                   choices=['present', 'absent']),
        server_url=dict(required=True,
                        fallback=(env_fallback,
                        ['FOREMAN_SERVER_URL', 'FOREMAN_SERVER', 'FOREMAN_URL'])),
        username=dict(required=True,
                      fallback=(env_fallback, ['FOREMAN_USERNAME', 'FOREMAN_USER'])),
        password=dict(required=True,
                      no_log=True,
                      fallback=(env_fallback, ['FOREMAN_PASSWORD'])),
        validate_certs=dict(type='bool',
                            default=True,
                            fallback=(env_fallback, ['FOREMAN_VALIDATE_CERTS'])),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_webhook=[],
        updates=[],
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    name=module.params['name']
    webhook_target_url=module.params['webhook_target_url']
    webhook_http_method=module.params['webhook_http_method']
    webhook_http_content_type=module.params['webhook_http_content_type']
    webhook_event=module.params['webhook_event']
    webhook_template=module.params['webhook_template']
    webhook_enabled=module.params['webhook_enabled']
    webhook_verify_ssl=module.params['webhook_verify_ssl']
    webhook_ssl_ca_certs=module.params['webhook_ssl_ca_certs']
    webhook_user=module.params['webhook_user']
    webhook_password=module.params['webhook_password']
    webhook_http_headers=module.params['webhook_http_headers']
    webhook_proxy_authorization=module.params['webhook_proxy_authorization']
    state=module.params['state']
    server_url=module.params['server_url']
    username=module.params['username']
    password=module.params['password']
    validate_certs=module.params['validate_certs']

    session = ApiAccess(server_url, username, password, validate_certs)

    # The ID of the webhook template in the database. Or None if
    # the webhook template does not yet exist
    webhook_id=None
    current_webhook = {}
    find_webhook, statuscode = session.get(f"/api/v2/webhooks?search={name}")
    if statuscode not in [200,404]:
        module.fail_json(f"Server {server_url} returned {statuscode} for webhook search")
    if statuscode == 200:
        if len(find_webhook['results']) > 0:
            webhook_id=find_webhook['results'][0]['id']

    # List of all the changes to perform.
    # Provided in the JSON format we need to submit to the server
    updates_webhook={}

    webhook_templates, statuscode = \
        session.get("/api/v2/webhook_templates")
    if statuscode != 200:
        module.fail_json(f"Server {server_url} returned {statuscode} for webhook templates")

    change_needed = False
    if webhook_id is None:
        if state == "present":
            change_needed = True
            # create list of changes to perform
            webhook_update={}
            webhook_update['name']=name
            webhook_update['target_url']=webhook_target_url
            webhook_update['http_method']=webhook_http_method
            webhook_update['http_content_type']=webhook_http_content_type
            webhook_update['event']=webhook_event
            wh_found = False
            for wh_template in webhook_templates['results']:
                if wh_template['name'] == webhook_template:
                    wh_found = True
                    webhook_update['webhook_template_id'] = wh_template['id']
            if not wh_found:
                module.fail_json(f"Webhook template {webhook_template} not found")
            webhook_update['enabled']=webhook_enabled
            webhook_update['verify_ssl']=webhook_verify_ssl
            webhook_update['ssl_ca_certs']=webhook_ssl_ca_certs
            webhook_update['user']=webhook_user
            webhook_update['password']=webhook_password
            webhook_update['http_headers']=webhook_http_headers
            webhook_update['proxy_authorization']=webhook_proxy_authorization

        updates_webhook['webhook']=webhook_update

    else:
        if state == "absent":
            change_needed = True
        else:
            # Load all details about existing webhook template
            current_webhook, statuscode = \
                session.get(f"/api/v2/webhooks/{webhook_id}")
            if statuscode != 200:
                module.fail_json(f"Server {server_url} returned {statuscode} for webhook")

            # compare all the desired fields with the existing ones
            webhook_update={}
            compare_set_field(webhook_update, current_webhook, webhook_target_url, 'target_url')
            compare_set_field(webhook_update, current_webhook, webhook_http_method, 'http_method')
            compare_set_field(webhook_update, current_webhook,
                              webhook_http_content_type, 'http_content_type')
            compare_set_field(webhook_update, current_webhook, webhook_event, 'event')
            # For Webhook templates, we need to look up the id
            if webhook_template is not None:
                wh_found = False
                for wh_template in webhook_templates['results']:
                    if wh_template['name'] == webhook_template:
                        wh_found = True
                        if current_webhook['webhook_template']['id'] != wh_template['id']:
                            webhook_update['webhook_template_id'] = wh_template['id']
                if not wh_found:
                    module.fail_json(f"Webhook template {webhook_template} not found")
            compare_set_field(webhook_update, current_webhook, webhook_enabled, 'enabled')
            compare_set_field(webhook_update, current_webhook, webhook_verify_ssl, 'verify_ssl')
            compare_set_field(webhook_update, current_webhook,
                              webhook_ssl_ca_certs, 'ssl_ca_certs')
            compare_set_field(webhook_update, current_webhook, webhook_user, 'user')
            compare_set_field(webhook_update, current_webhook, webhook_password, 'password')
            compare_set_field(webhook_update, current_webhook,
                              webhook_http_headers, 'http_headers')
            compare_set_field(webhook_update, current_webhook,
                              webhook_proxy_authorization, 'proxy_authorization')

            if len(webhook_update) > 0:
                change_needed = True
                updates_webhook['webhook']=webhook_update
                updates_webhook['id'] = webhook_id

    result['original_webhook']=current_webhook
    result['updates'] = updates_webhook
    result['changed'] = change_needed

    # # if the user is working with this module in only check mode we do not
    # # want to make any changes to the environment, just return the current
    # # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # Update webhook template
    if change_needed:
        if state == "absent":
            output, statuscode = session.delete(f"/api/v2/webhooks/{webhook_id}")
        else:
            if webhook_id is None:
                # New, We need a POST to /api/v2/webhooks
                output, statuscode = session.post("/api/v2/webhooks", updates_webhook)
            else:
                # Update, we need a PUT
                output, statuscode = \
                    session.put(f"/api/v2/webhooks/{webhook_id}", updates_webhook)

        if not 200 <= statuscode < 300:
            module.fail_json(msg=f'Update failed. Status {statuscode}, output {output}', **result)

        result['statuscode']=statuscode
        result['output']=output

    logging.debug(json.dumps(result, indent=2, sort_keys=True))

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    "Main entry point"

    logging.basicConfig(level=logging.DEBUG)
    run_module()


if __name__ == '__main__':
    main()
