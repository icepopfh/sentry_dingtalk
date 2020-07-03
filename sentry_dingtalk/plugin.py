"""
sentry_dingtalk.models
~~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2018 by zhangshijie, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.

:2020.6.23 Modified by icepopfh : v1.0
:2020.7.3 Modified by icepopfh : v1.1
"""

from __future__ import absolute_import

import time
import hmac
import hashlib
import base64
import urllib
import json
import requests
import logging
import six
import sentry

from django import forms
from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from sentry.exceptions import PluginError
from sentry.plugins.bases import notify
from sentry.http import is_valid_url, safe_urlopen
from sentry.utils.safe import safe_execute

from sentry.utils.http import absolute_uri
from django.core.urlresolvers import reverse

def validate_urls(value, **kwargs):
    output = []
    for url in value.split('\n'):
        url = url.strip()
        if not url:
            continue
        if not url.startswith(('http://', 'https://')):
            raise PluginError('Not a valid URL.')
        if not is_valid_url(url):
            raise PluginError('Not a valid URL.')
        output.append(url)
    return '\n'.join(output)

def validate_secret(value, **kwargs):
    output = []
    for i in value.split('\n'):
        secret = i.strip()
        output.append(secret)
    return '\n'.join(output)


class DingtalkForm(notify.NotificationConfigurationForm):
    urls = forms.CharField(
        label=_('Dingtalk robot url'),
        widget=forms.Textarea(attrs={
            'class': 'span6', 'placeholder': 'https://oapi.dingtalk.com/robot/send?access_token=9bacf9b193f'}),
        help_text=_('Enter dingtalk robot url.'))
    secret = forms.CharField(
        label=_('Dingtalk robot secret'),
        widget=forms.Textarea(attrs={
            'class': 'span6', 'placeholder': 'xxxxxxxxx'}),
        help_text=_('Enter dingtalk robot secret.'))

    def clean_url(self):
        value = self.cleaned_data.get('url')
        return validate_urls(value)
    
    def clean_secret(self):
        value = self.cleaned_data.get('secret')
        return validate_secret(value)

 
class DingtalkPlugin(notify.NotificationPlugin):
    author = 'icepopfh'
    author_url = 'https://github.com/icepopfh/sentry_dingtalk.git'
    version = sentry.VERSION
    description = "Integrates dingtalk robot(szzsmw customized version)"
    resource_links = [
        ('Bug Tracker', 'https://github.com/icepopfh/sentry_dingtalk.git'),
        ('Source', 'https://github.com/icepopfh/sentry_dingtalk.git'),
    ]

    slug = 'dingtalk'
    title = 'dingtalk'
    conf_title = title
    conf_key = 'dingtalk'  

    project_conf_form = DingtalkForm
    timeout = getattr(settings, 'SENTRY_DINGTALK_TIMEOUT', 3) 
    logger = logging.getLogger('sentry.plugins.dingtalk')

    def is_configured(self, project, **kwargs):
        return bool(self.get_option('urls', project))

    def get_config(self, project, **kwargs):
        return [{
            'name': 'urls',
            'label': 'dingtalk robot url',
            'type': 'textarea',
            'help': 'Enter dingtalk robot url.',
            'placeholder': 'https://oapi.dingtalk.com/robot/send?access_token=abcdefg',
            'validators': [validate_urls],
            'required': False
        },{
            'name': 'secret',
            'label': 'dingtalk robot secret',
            'type': 'textarea',
            'help': 'Enter dingtalk robot secret.',
            'placeholder': 'xxxxxxxxx',
            'validators': [validate_secret],
            'required': False
        }]

    def get_webhook_urls(self, project):
        url = self.get_option('urls', project)
        if not url:
            return ''
        return url
    
    def get_webhook_secret(self, project):
        secret = self.get_option('secret', project)
        return secret

    def send_webhook(self, url, payload):
        return safe_urlopen(
            url=url,
            json=payload,
            timeout=self.timeout,
            verify_ssl=False,
        )

    def get_group_url(self, group):
        '''
        return absolute_uri(reverse('sentry-group', args=[
            group.organization.slug,
            group.project.slug,
            group.id,
        ]))
        '''
        return absolute_uri(group.get_absolute_url())

    def notify_users(self, group, event, *args, **kwargs):
        Initialize_url = self.get_webhook_urls(group.project)
        link = self.get_group_url(group)
        timestamp = long(round(time.time() * 1000))
        secret = self.get_webhook_secret(group.project)
        secret_enc = bytes(secret).encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        string_to_sign_enc = bytes(string_to_sign).encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.quote_plus(base64.b64encode(hmac_code))
        url = "%s&timestamp=%s&sign=%s"  %(Initialize_url,timestamp,sign)
        message_format = '[%s] %s   %s'
        message = message_format % (event.server_name, event.message, link)
        data = {"msgtype": "text",
                    "text": {
                        "content": message
                    }
                }
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        r = requests.post(url, data=json.dumps(data), headers=headers)

