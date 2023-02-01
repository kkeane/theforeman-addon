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
Module for managing association between hosts and host_collections.
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
module: host_hostcollections

short_description: Manages the association of hosts and host_collections

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: This module will associate a given host with a list of host_collections.

options:
    host:
        description: This is host name
        required: true
        type: str
    host_collections:
        description:
            - List of all host collections this host should be a member of
            - The host will be removed from all other collections
        required: true
        type: List. Element Type: str
    state:
        description: State of the entity
        Choices:
            - present (add the given host collections)
            - override (add the given host collections and remove all others)
            - absent  (remove the given host collections)
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
- name: Add a hostgroup
  host_hostcollections:
    host: myhost.example.com
    host_collections:
      - samplecollection1
      - samplecollection2
'''

RETURN = r'''
original_hostcollections:
    description: Comma-separated string with the names of all preexisting host collections
    type: str
    returned: always
    sample: 'Collection 1,Collection 2'
new_hostcollections:
    description: Comma-separated string with the names of all host collections after this module ran
    type: str
    returned: always
    sample: 'Collection 2,Collection 3'
added:
    description: Comma-separated string with the names of all host collections added
    type: str
    returned: always
    sample: 'Collection 3'
removed:
    description: Comma-separated string with the names of all host collections that have been removed
    type: str
    returned: always
    sample: 'Collection 1'
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

def hostcollection_ids_to_text(host_collection, all_host_collections):
    """
    Convert the list of IDs given as host_collection into
    a comma-separated list of host collection names.
    Make it sorted so it becomes easier to use for a human.
    """
    output_array=set()
    for h_c in host_collection:
        for all_h_c in all_host_collections['results']:
            if h_c == all_h_c['id']:
                output_array.add(all_h_c['name'])
    return ','.join(sorted(output_array))

def host_collection_names_to_ids(input_set, all_hcs):
    """
    Returns a set of IDs that match the host_collection names in the
    input set

    input_set: a set of host collection names.
    all_hcs: a list of all host collections available in the system

    output: a set of host_collection IDs. Any names not found will be
            silently ignored.
    """
    # Note that we are iterating "backwards" over all available
    # host collections, to find those that the caller requested.
    # A side effect is that we will not see any non-existent
    # host collections.
    output_set = set()
    for h_c in all_hcs:
        if h_c['name'] in input_set:
            output_set.add(h_c['id'])
    return output_set

def run_module():
    """
    Run the module
    """

    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        host=dict(type='str', required=True),
        host_collections=dict(type='list', required=True),
        state=dict(type='str',
                   required=False,
                   default='present',
                   choices=['present','absent','override']),
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
        original_hostcollections='',
        new_hostcollections='',
        added='',
        removed='',
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    host=module.params['host']
    host_collections=module.params['host_collections']
    state=module.params['state']
    server_url=module.params['server_url']
    username=module.params['username']
    password=module.params['password']
    validate_certs=module.params['validate_certs']

    session = ApiAccess(server_url, username, password, validate_certs)

    current_host_collections = set()
    desired_host_collections = set()
    find_host, statuscode = session.get(f"/api/v2/hosts?search={host}")
    all_host_collections, statuscode2 = session.get("/katello/api/host_collections?per_page=1000000")
    if statuscode != 200:
        module.fail_json(f"Server {server_url} returned {statuscode} for host search")
    if statuscode2 != 200:
        module.fail_json(f"Server {server_url} returned {statuscode2} for host collections")
    if len(find_host['results']) != 1:
        module.fail_json(f"Host {host} was not found")

    hostid = find_host['results'][0]['id']
    locationid = find_host['results'][0]['location_id']
    organizationid = find_host['results'][0]['organization_id']
    logging.debug("Host ID is %s", hostid)
    hostdetails, statuscode = session.get(f"/api/v2/hosts/{hostid}")
    if statuscode != 200:
        module.fail_json(f"Server {server_url} returned {statuscode} for host details")

    current_host_collections_json = hostdetails['host_collections']
    for c_h_c in current_host_collections_json:
        # map to just ID numbers. Make the new list sorted while
        # we are at it.
        current_host_collections.add(c_h_c['id'])

    desired_host_collections = \
        host_collection_names_to_ids(host_collections, all_host_collections['results'])

    # compare current host collection with desired one
    new_host_collections=set()
    if state == 'override':
        new_host_collections = desired_host_collections
    elif state == 'present':
        new_host_collections = current_host_collections.union(desired_host_collections)
    elif state == 'absent':
        new_host_collections = current_host_collections.difference(desired_host_collections)

    to_add = new_host_collections.difference(current_host_collections)
    to_remove = current_host_collections.difference(new_host_collections)

    result['original_host_collections']=hostcollection_ids_to_text(
        current_host_collections, all_host_collections)
    result['new_host_collections']=hostcollection_ids_to_text(
        new_host_collections, all_host_collections)
    result['added']=hostcollection_ids_to_text(to_add, all_host_collections)
    result['removed']=hostcollection_ids_to_text(to_remove, all_host_collections)

    change_needed = False
    if len(to_add)>0 or len(to_remove) > 0:
        change_needed = True

    result['changed'] = change_needed

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # Update host collection
    if change_needed:
        args = {}
        args['location_id'] = locationid
        args['organization_id'] = organizationid
        args['host_id'] = hostid
        args['host_collection_ids'] = list(new_host_collections)
        output, statuscode = session.put(f"/api/v2/hosts/{hostid}/host_collections", args)
        if statuscode != 200:
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
