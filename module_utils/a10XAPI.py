# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c), Michael DeHaan <michael.dehaan@gmail.com>, 2012-2013
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
import httplib

import re
import urlparse

from ansible.module_utils.basic import json
from ansible.module_utils.network import NetworkModule, NetworkError, ModuleStub
from ansible.module_utils.network import add_argument, register_transport, to_list
from ansible.module_utils.shell import CliBase
from ansible.module_utils.netcli import Command
from ansible.module_utils.urls import fetch_url, url_argument_spec


AXAPI_PORT_PROTOCOLS = {
         'tcp': 2,
         'udp': 3,
}

AXAPI_VPORT_PROTOCOLS = {
         'tcp': 2,
         'udp': 3,
         'fast-http': 9,
         'http': 11,
         'https': 12,
}

VALID_PORT_FIELDS = ['port-number', 'protocol', 'status']

class XAPI():

    def __init__(self):
        self.urllogon = "/axapi/v3/auth"
        self.urllogoff = "/axapi/v3/logoff"
        self.username="admin"
        self.password="a10"
        self.host="127.0.0.1"
        self.write_config=False
        self.JSON_INDENT = 4
        self.token = None
        self._connected = False
        self.default_output = 'text'
        self.enable_debug = False

    def axapi_failure(result):
        if 'response' in result and result['response'].get('status') == 'fail':
            return True
        return False


    def validate_ports(self, module, ports):
        for item in ports:
            for key in item:
                if key not in VALID_PORT_FIELDS:
                    module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

            # validate the port number is present and an integer
            if 'port-number' in item:
                try:
                    item['port-number'] = int(item['port-number'])
                except:
                    module.fail_json(msg="port-number entries in the port definitions must be integers")
            else:
                module.fail_json(msg="port definitions must define the port-number field")

            # validate the port protocol is present, and convert it to
            # the internal API integer value (and validate it)
            if 'protocol' in item:
                protocol = self.axapi_get_port_protocol(item['protocol'])
                if not protocol:
                    module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_PORT_PROTOCOLS))
                else:
                    item['protocol'] = protocol
            else:
                module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_PORT_PROTOCOLS))

            # convert the status to the internal API integer value
            if 'status' in item:
                item['status'] = self.axapi_enabled_disabled(item['status'])
            else:
                item['status'] = 1


    def axapi_get_port_protocol(self, protocol):
        return AXAPI_PORT_PROTOCOLS.get(protocol.lower(), None)

    def axapi_get_vport_protocol(self, protocol):
        return AXAPI_VPORT_PROTOCOLS.get(protocol.lower(), None)

    def a10_argument_spec(self):
        return dict(
            host=dict(type='str', required=True),
            username=dict(type='str', aliases=['user', 'admin'], required=True),
            password=dict(type='str', aliases=['pass', 'pwd'], required=True, no_log=True),
            write_config=dict(type='bool', default=False)
        )

    def print_json(self, json_input):
        if self.enable_debug:
            print json.dumps(json_input, indent = self.JSON_INDENT)

    def post(self, module, uri, payload):
        self.host= module.params['host']
        conn = httplib.HTTPConnection(self.host)
        json_payload = json.dumps(payload)
        if self.enable_debug:
            print "\nPOST "+ uri + "\nPayload:\n"
        self.print_json(json_input = payload)
        c = conn.request("POST", uri, json_payload, self.headers)
        try:
            conn_response = conn.getresponse()
            json_response = conn_response.read()
            response = json.loads(json_response.replace('\n', ''))
            if self.enable_debug:
                print "HTTP Status Code: %d" % (conn_response.status)
                print "HTTP Reason: %s" % (conn_response.reason)

            if (conn_response.status != 204):
                self.print_json(json_input = response)

            return (conn_response.status, response)
        except Exception as ex:
            module.fail_json(msg="failed to connect (status code %s), error was %s" % (conn_response.status, conn_response.reason))
            #print "failed to connect (status code %s), error was %s" % (conn_response.status, conn_response.reason)
            raise ex


    def get(self, module, uri):
        self.host= module.params['host']
        conn = httplib.HTTPConnection(self.host)
        conn.request("GET", uri, body=None, headers = self.headers)
        if self.enable_debug:
            print "\nGET " + uri
        try:
            conn_response = conn.getresponse()
            json_response = conn_response.read()
            response = ""
            if conn_response.status != 204:
                response = json.loads(json_response.replace('\n', ''))
            if self.enable_debug:
                print self.print_json(response)
            if self.enable_debug:
                print "HTTP Status Code: %d" % (conn_response.status)
                print "HTTP Reason: %s" % (conn_response.reason)
            return (conn_response.status, response)
        except Exception as ex:
            print "failed to connect (status code %s), error was %s" % (conn_response.status, conn_response.reason)
            raise ex


    def put(self, uri, payload):
        conn = httplib.HTTPConnection(self.host)
        json_payload = json.dumps(payload)
        c = conn.request("PUT", uri, json_payload, self.headers)
        if self.enable_debug:
            print "\nPUT "+ uri + "\nPayload:\n"
        self.print_json(json_input = payload)
        try:
            conn_response = conn.getresponse()
            json_response = conn_response.read()
            response = ""
            if conn_response.status != 204:
                response = json.loads(json_response.replace('\n', ''))
                print self.print_json(response)
            print "HTTP Status Code: %d" % (conn_response.status)
            print "HTTP Reason: %s" % (conn_response.reason)
            return (conn_response.status, response)
        except Exception as ex:
            raise ex


    def delete(self, module, uri):
        conn = httplib.HTTPConnection(self.host)
        conn.request("DELETE", uri, body = None, headers = self.headers)
        if self.enable_debug:
            print "\nDELETE " + uri
        try:
            conn_response = conn.getresponse()
            json_response = conn_response.read()
            response = ""
            if conn_response.status != 204:
                response = json.loads(json_response.replace('\n', ''))
                print self.print_json(response)
            if self.enable_debug:
                print "HTTP Status Code: %d" % (conn_response.status)
                print "HTTP Reason: %s" % (conn_response.reason)
            return (conn_response.status, response)
        except Exception as ex:
            module.fail_json(msg="failed to connect (status code %s), error was %s" % (conn_response.status, conn_response.reason))
            raise ex



    def logon(self, module):

        self.host= module.params['host']
        #host = module.params['host']
        self._connected = True

        if self.enable_debug:
            print "\n***** LOGON *****"

        json_content_type_header = {'Content-type': 'application/json'}

        #conn = httplib.HTTPConnection(self.host)
        conn = httplib.HTTPConnection(self.host)
        credentials_dict = {}
        credentials_dict["credentials"] = {}
        credentials_dict["credentials"]["username"] = module.params['username']
        credentials_dict["credentials"]["password"] = module.params['password']

        conn.request("POST", self.urllogon, json.dumps(credentials_dict), json_content_type_header)

        try:
            response = json.loads(conn.getresponse().read())
            if "authresponse" in response:
                signature = str(response['authresponse']['signature'])
                self.token = signature
                self.headers = {'Content-type': 'application/json', 'Authorization': "A10 %s" % signature}
            else:
                module.fail_json(msg="Unable to logon" )
                raise Exception("Unable to logon")
        except Exception as ex:
            module.fail_json(msg="failed to connect , error was %s" % (ex.message))
            #print "failed to connect to %s" % (self.host)
            raise Exception(ex.message)


    def logoff(self, module):
        self.host= module.params['host']
        if self.enable_debug:
            print "\n***** LOGOFF *****"
        conn = httplib.HTTPConnection(self.host)
        #conn.request("POST", self.LOGOFF_URI, "", self.headers)
        conn.request("GET", self.urllogoff, "", headers = self.headers)

        self._connected = False

        response = conn.getresponse().read()
        return response

    def axapi_enabled_disabled(self,flag):
         '''
         The axapi uses 0/1 integer values for flags, rather than strings
         or booleans, so convert the given flag to a 0 or 1. For now, params
         are specified as strings only so thats what we check.
         '''
         if flag == 'enabled':
             return 1
         else:
             return 0

XAPI = register_transport('axapi')(XAPI)
