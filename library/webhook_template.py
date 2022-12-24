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
Module for managing webhook templates in Foreman/Satellite
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
module: webhook_template

short_description: Manages Webhook Templates

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: This module will create/update a Webhook template

options:
    name:
        description: This is name of the webhook template
        required: true
        type: str
    description:
        description: This is a description of the webhook template
        required: false
        type: str
    state:
        description: State of the entity
        Choices:
            - present (add the given host collections)
            - absent  (remove the given host collections)
    organization:
        description: Name of the organization that this template belongs to
        required: true
        type: str
    locations:
        description: Name of the locations that this template is valid for.
        required: true when state == "present"
        type: list. Element Type: str
    snippet:
        description: Identifies whether this is a full emplate or a snippet
        required: false when state == "present"
        default: false
        type: bool
    default:
        description: Identifies whether this is a default template
        required: false when state == "present"
        default: false
        type: bool
    template:
        description: content of the template. This can have multiple lines
        required: true when state == "present"
        type: str
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
- name: Add a web template
  web_template:
    name: My new template
    description: This is an example template
    organization: Default Organization
    locations:
      - Anywhere
    snippet: False
    template: <%= @object %>
    server_url: foremanserver.example.com
    username: foreman_admin
    password: some_supersecure_password

Notes:
- If the template already exists, it must not be locked.

'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
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

        self._sat_session=requests.Session()
        self._sat_session.verify=validate_certs
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
        return result.json() , result.status_code

    def put(self, location: str, args) -> tuple:
        """
        Performs a PUT using the passed URL location
        """

        logging.debug("PUT %s", location)
        result = self._sat_session.put(self._server_url + location, json=args)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json() , result.status_code

    def post(self, location: str, args) -> tuple:
        """
        Performs a POST using the passed URL location
        """

        logging.debug("POST %s", location)
        result = self._sat_session.post(self._server_url + location, json=args)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json() , result.status_code

    def delete(self, location: str) -> tuple:
        """
        Performs a DELETE using the passed URL location
        """

        logging.debug("DELETE %s", location)
        result = self._sat_session.delete(self._server_url + location)
        logging.debug(result)
        logging.debug(json.dumps(result.json(), indent=2, sort_keys=True))
        return result.json() , result.status_code

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

def organization_name_to_id(input_str, all_organizations):
    """
    Retrieve the ID for an organization with the given name
    Return value will be None if the organization does not
    exist.
    """

    for org in all_organizations:
        if org['name']==input_str:
            return org['id']
    return None

def organization_id_to_name(input_id, all_organizations):
    """
    Retrieve the ID for an organization with the given name
    Return value will be None if the organization does not
    exist.
    """

    for org in all_organizations:
        if org['id']==input_id:
            return org['name']
    return None

def run_module():
    """
    Run the module
    """

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        name=dict(type='str', required=True),
        description=dict(type='str', required=False),
        organization=dict(type='str', required=True),
        locations=dict(type='list', required=True),
        snippet=dict(type='bool', default=False),
        default=dict(type='bool', default=False),
        template=dict(type='str', required=True),
        state=dict(type='str',
                   required=False,
                   default='present',
                   choices=['present','absent']),
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
        original_webhook_template='',
        updates=''
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
    description=module.params['description']
    organization_name=module.params['organization']
    locations=module.params['locations']
    snippet=module.params['snippet']
    isdefault=module.params['default']
    template=module.params['template']
    state=module.params['state']
    server_url=module.params['server_url']
    username=module.params['username']
    password=module.params['password']
    validate_certs=module.params['validate_certs']

    session = ApiAccess(server_url, username, password, validate_certs)

    # The ID of the webhook template in the database. Or None if
    # the webhook template does not yet exist
    webhook_template_id=None
    current_webhook_template = {}
    find_webhook_template, statuscode = session.get(f"/api/v2/webhook_templates?search={name}")
    if statuscode not in [200,404]:
        module.fail_json(f"Server {server_url} returned {statuscode} for webhook template search")
    if statuscode == 200:
        if len(find_webhook_template['results']) > 0:
            webhook_template_id=find_webhook_template['results'][0]['id']

    all_locations, statuscode = session.get("/api/v2/locations")
    if statuscode != 200:
        module.fail_json(f"Server {server_url} returned {statuscode} for locations")

    all_organizations, statuscode = session.get("/api/v2/organizations")
    if statuscode != 200:
        module.fail_json(f"Server {server_url} returned {statuscode} for organizations")
    desired_organization_id = organization_name_to_id(organization_name, all_organizations['results'])
    desired_location_ids = location_names_to_ids(locations, all_locations['results'])

    # List of all the changes to perform.
    # Provided in the JSON format we need to submit to the server
    updates_webhook_template={}

    if webhook_template_id is None:
        if state == "present":
            change_needed = True
            # create list of changes to perform
            updates_webhook_template['organization_id']=desired_organization_id
            template_update={}
            template_update['name']=name
            template_update['locations']=list(desired_location_ids)
            if description is not None:
                template_update['description']=description
            if template is not None:
                template_update['template']=template
            template_update['snippet']=snippet
            template_update['default']=isdefault
            template_update['locked']=False
            template_update['default']=False
            template_update['audit_comment'] = "Created by Ansible module webhook_template"

        # We do not allow updating the organization ids field.
        updates_webhook_template['webhook_template']=template_update

    else:
        if state == "absent":
            change_needed = True
        else:
            # Load all details about existing webhook template
            current_webhook_template, statuscode = \
                session.get(f"/api/v2/webhook_templates/{webhook_template_id}")
            if statuscode != 200:
                module.fail_json(f"Server {server_url} returned {statuscode} for webhook template")

            organizationid = current_webhook_template['results'][0]['organization_id']
            if organizationid != desired_organization_id:
                otherorgname=organization_id_to_name(organizationid, all_organizations)
                module.fail_json(f"Existing template {name} belongs to '{otherorgname}'")
            locationids = location_list_to_ids(current_webhook_template['results'][0]['locations'])

            # TODO: compare all the desired fields with the existing ones
            template_update={}
            if locationids.symmetric_difference(desired_location_ids):
                # add to list of changes to make
                template_update['locations']=list(desired_location_ids)
            if not description is None:
                if description != current_webhook_template['results'][0]['description']:
                    template_update['description']=description
            if not template is None:
                if template != current_webhook_template['results'][0]['template']:
                    template_update['template']=template
            if snippet != current_webhook_template['results'][0]['snippet']:
                template_update['snippet']=snippet
            if isdefault != current_webhook_template['results'][0]['default']:
                template_update['default']=isdefault

            if len(template_update) > 0:
                change_needed = True
                template_update['audit_comment'] = "Updated by Ansible module webhook_template"
                updates_webhook_template['webhook_template']=template_update
                updates_webhook_template['id'] = webhook_template_id

    result['original_webhook_template']=current_webhook_template
    result['updates'] = updates_webhook_template
    result['changed'] = change_needed

    # # if the user is working with this module in only check mode we do not
    # # want to make any changes to the environment, just return the current
    # # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # Update webhook template
    if change_needed:
        if state == "absent":
            output, statuscode = session.delete(f"/api/v2/webhook_templates/{webhook_template_id}")
        else:
            if webhook_template_id is None:
                # We need a POST to /api/v2/webhook_templates
                output, statuscode = session.post("/api/v2/webhook_templates",
                                                updates_webhook_template)
            else:
                # PUT to /api/webhook_templates/:id
                output, statuscode = \
                    session.put(f"/api/v2/webhook_templates/{webhook_template_id}",
                                updates_webhook_template)

        if not 200 <= statuscode < 300:
            module.fail_json(msg=f'Update failed. Status {statuscode}, output {output}', **result)

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
