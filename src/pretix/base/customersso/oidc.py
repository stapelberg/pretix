import logging
from urllib.parse import urlencode, urljoin

import requests
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from requests import RequestException

logger = logging.getLogger(__name__)


def oidc_validate_and_complete_config(config):
    for k in ("base_url", "client_id", "client_secret", "uid_field", "email_field"):
        if not config.get(k):
            raise ValidationError(_('Configuration option "{name}" is missing.').format(name=k))

    conf_url = urljoin(config["base_url"], "/.well-known/openid-configuration")
    try:
        resp = requests.get(conf_url)
        resp.raise_for_status()
        provider_config = resp.json()
    except RequestException as e:
        raise ValidationError(_('Unable to retrieve configuration from "{url}". Error message: "{error}".').format(
            url=conf_url,
            error=str(e)
        ))
    except ValueError as e:
        raise ValidationError(_('Unable to retrieve configuration from "{url}". Error message: "{error}".').format(
            url=conf_url,
            error=str(e)
        ))

    if not provider_config.get("authorization_endpoint"):
        raise ValidationError(_('Incompatible SSO provider: "{error}".').format(
            error="authorization_endpoint not set"
        ))

    if not provider_config.get("userinfo_endpoint"):
        raise ValidationError(_('Incompatible SSO provider: "{error}".').format(
            error="userinfo_endpoint not set"
        ))

    if not provider_config.get("token_endpoint"):
        raise ValidationError(_('Incompatible SSO provider: "{error}".').format(
            error="token_endpoint not set"
        ))

    if "code" not in provider_config.get("response_types_supported", []):
        raise ValidationError(_('Incompatible SSO provider: "{error}".').format(
            error=f"provider supports response types {','.join(provider_config['response_types_supported'])}, but we only support 'code'."
        ))

    if "query" not in provider_config.get("response_modes_supported", []):
        raise ValidationError(_('Incompatible SSO provider: "{error}".').format(
            error=f"provider supports response modes {','.join(provider_config['response_modes_supported'])}, but we only support 'query'."
        ))

    if "authorization_code" not in provider_config.get("grant_types_supported", []):
        raise ValidationError(_('Incompatible SSO provider: "{error}".').format(
            error=f"provider supports grant types {','.join(provider_config['grant_types_supported'])}, but we only support 'authorization_code'."
        ))

    if "openid" not in config["scope"].split(" "):
        raise ValidationError(
            _('You are not requesting "{scope}".').format(
                scope="openid",
            ))

    for scope in config["scope"].split(" "):
        if scope not in provider_config.get("scopes_supported", []):
            raise ValidationError(_('You are requesting scope "{scope}" but provider only supports these: {scopes}.').format(
                scope=scope,
                scopes=", ".join(provider_config.get("scopes_supported", []))
            ))

    for k, v in config.items():
        if k.endswith('_field'):
            if v not in provider_config.get("claims_supported", []):  # https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                raise ValidationError(_('You are requesting field "{field}" but provider only supports these: {fields}.').format(
                    field=v,
                    fields=", ".join(provider_config.get("claims_supported", []))
                ))

    config['provider_config'] = provider_config
    return config


def oidc_authorize_url(provider, state, redirect_uri):
    endpoint = provider.configuration['provider_config']['authorization_endpoint']
    params = {
        # https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
        # https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
        'response_type': 'code',
        'client_id': provider.configuration['client_id'],
        'scope': provider.configuration['scope'],
        'state': state,
        'redirect_uri': redirect_uri,
    }
    return endpoint + '?' + urlencode(params)


def oidc_validate_authorization(provider, code, redirect_uri):
    endpoint = provider.configuration['provider_config']['token_endpoint']
    params = {
        # https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        # https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
    }
    try:
        resp = requests.post(
            endpoint,
            data=params,
            headers={
                'Accept': 'application/json',
            },
            auth=(provider.configuration['client_id'], provider.configuration['client_secret']),
        )
        resp.raise_for_status()
        data = resp.json()
    except RequestException:
        logger.exception('Could not retrieve authorization token')
        raise ValidationError(
            _('Login was not successful. Error message: "{error}".').format(
                error='could not reach login provider',
            )
        )

    if 'access_token' not in data:
        raise ValidationError(
            _('Login was not successful. Error message: "{error}".').format(
                error='access token missing',
            )
        )

    endpoint = provider.configuration['provider_config']['userinfo_endpoint']
    try:
        # https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        resp = requests.get(
            endpoint,
            headers={
                'Authorization': f'Bearer {data["access_token"]}'
            },
        )
        resp.raise_for_status()
        userinfo = resp.json()
    except RequestException:
        logger.exception('Could not retrieve user info')
        raise ValidationError(
            _('Login was not successful. Error message: "{error}".').format(
                error='could not fetch user info',
            )
        )

    if 'email_verified' in userinfo and not userinfo['email_verified']:
        # todo: how universal is this, do we need to make this configurable?
        raise ValidationError(_('The email address on this account is not yet verified. Please first confirm the '
                                'email address in your customer account.'))

    profile = {}
    for k, v in provider.configuration.items():
        if k.endswith('_field'):
            profile[k[:-6]] = userinfo.get(v)

    if not profile.get('uid'):
        raise ValidationError(
            _('Login was not successful. Error message: "{error}".').format(
                error='could not fetch user id',
            )
        )

    if not profile.get('email'):
        raise ValidationError(
            _('Login was not successful. Error message: "{error}".').format(
                error='could not fetch user email',
            )
        )

    return profile
