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

from keystoneauth1 import exceptions
from keystoneauth1 import loading
from keystoneauth1.extras.rba import identity
from keystoneauth1.loading._plugins.identity import v3

class RiskBasedAuth(loading.BaseV3Loader):

    @property
    def plugin_class(self):
        return identity.V3RBA

    @property
    def available(self):
        return identity.V3RBA is not None

    def get_options(self):
        options = super(RiskBasedAuth, self).get_options()
        v3._add_common_identity_options(options)

        options.extend([
            loading.Opt('features',
                        type=dict,
                        help='RBA features',
                        required=False),
            loading.Opt('passcode',
                        secret=True,
                        prompt='RBA passcode:',
                        help='Users passcode',
                        required=False)
        ])

        return options

    def load_from_options(self, **kwargs):
        v3._assert_identity_options(kwargs)
        if not (kwargs.get('passcode') and kwargs.get('features')):
            m = ('You have to provide a user and either features '
                 'or a passcode.')
            raise exceptions.OptionError(m)
        return super(RiskBasedAuth, self).load_from_options(**kwargs)
