# Copyright 2022 Vincent Unsel
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import base

__all__ = ('RBAMethod', 'RBA')

class RBAException(Exception):
    """Base RBA plugin exception."""

class RBAMethod(base.AuthMethod):
    """Construct a risk-based authentication method for User with Features or Passcode

    :param string username: Username for authentication.
    :param string passcode: Passcode for authentication.
    :param string user_id: User ID for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.
    :param dict   features: Collected RBA feature informations.
    """

    _method_parameters = ['user_id',
                          'username',
                          'user_domain_id',
                          'user_domain_name',
                          'passcode',
                          'features']

    def __init__(self, **kwargs):
        super(RBAMethod, self).__init__(**kwargs)

    def get_auth_data(self, session, auth, headers, **kwargs):
        user = {}
        if self.passcode:
            user['passcode'] = self.passcode
        if self.features:
            user['features'] = self.features
        if self.user_id:
            user['id'] = self.user_id
        elif self.username:
            user['name'] = self.username
            if self.user_domain_id:
                user['domain'] = {'id': self.user_domain_id}
            elif self.user_domain_name:
                user['domain'] = {'name': self.user_domain_name}
        return 'rba', {'user': user}

    def get_cache_id_elements(self):
        return dict(('rba_%s' % p, getattr(self, p))
                    for p in self._method_parameters)


class RBA(base.AuthConstructor):
    """A plugin for authenticating with a username and passcode or features.

    :param string auth_url: Identity service endpoint for authentication.
    :param string passcode: Passcode for authentication.
    :param dict   features: Collected RBA feature informations.
    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.
    :param string trust_id: Trust ID for trust scoping.
    :param string system_scope: System information to scope to.
    :param string domain_id: Domain ID for domain scoping.
    :param string domain_name: Domain name for domain scoping.
    :param string project_id: Project ID for project scoping.
    :param string project_name: Project name for project scoping.
    :param string project_domain_id: Project's domain ID for project.
    :param string project_domain_name: Project's domain name for project.
    :param bool reauthenticate: Allow fetching a new token if the current one
                                is going to expire. (optional) default True
    """

    _auth_method_class = RBAMethod
