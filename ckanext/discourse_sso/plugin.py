from base64 import b64decode, b64encode
from ckan.plugins.toolkit import c, redirect_to, request
from pylons import config
import ckan.plugins.toolkit as toolkit
from urllib import urlencode
from urlparse import parse_qs, urljoin
import ckan.plugins as p
import hashlib
import hmac
import logging
import os

log = logging.getLogger(__name__)

# Environment variable takes priority
sso_secret = config.get('discourse.sso.secret')
sso_secret = os.environ.get('CKAN_DISCOURSE_SSO_SECRET', sso_secret)
if sso_secret is None:
    raise Exception("Config 'discourse.sso.secret' or environment variable "
                    "CKAN_DISCOURSE_SSO_SECRET must be set")

discourse_url = config.get('discourse.url')
discourse_url = os.environ.get('CKAN_DISCOURSE_URL', discourse_url)
if discourse_url is None:
    raise Exception("Config 'discourse.url' or environment variable "
                    "CKAN_DISCOURSE_URL must be set")


class DiscourseSSOPlugin(p.SingletonPlugin):

    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IConfigurer)

    def update_config(self, config_):
                toolkit.add_template_directory(config_, 'templates')

    def before_map(self, map_):
        # New route to custom action
        map_.connect(
            '/discourse/sso',
            controller='ckanext.discourse_sso.plugin:SSOController',
            action='sso')

        map_.connect( 
	    '/user/register',
             controller='ckanext.discourse_sso.plugin:UserNewController',
             action='register')


        return map_


class SSOController(p.toolkit.BaseController):

    def sso(self):
        if not c.user:
            redirect_to(controller='user',
                        action='login', came_from=request.url)

        if not signature_is_valid(request):
            raise Exception('Incorrect Discourse SSO Signature to CKAN')

        payload_b64 = make_payload(request, c.userobj)
        signature_hash = sign(payload_b64)
        query_string = urlencode({
            'sso': payload_b64,
            'sig': signature_hash.hexdigest(),
        })

        return_endpoint = urljoin(discourse_url, '/session/sso_login')
        redirect_to(return_endpoint + "?" + query_string)


def signature_is_valid(request):
    payload_b64 = request.params.get('sso')
    log.debug("Payload Base64-encoded %s", payload_b64)
    their_sig = request.params.get('sig')
    log.debug("Their signature %r", their_sig)

    log_safer_secret = "%s...hidden...%s" % (sso_secret[:3], sso_secret[-3:])
    log.debug("SSO Secret %s", log_safer_secret)

    hash = sign(payload_b64)
    our_sig = unicode(hash.hexdigest())
    log.debug("Our signature %r", our_sig)

    return hmac.compare_digest(their_sig, our_sig)


def make_payload(payload_b64, userobj):
    payload_b64 = request.params.get('sso')
    payload = b64decode(payload_b64)
    log.debug("Payload %s", payload)
    nonce = parse_qs(payload)['nonce'][0]
    log.debug("Nonce %s", nonce)

    return b64encode(urlencode({
        'nonce': nonce,
        'email': userobj.email,
        'external_id': userobj.id,
        'username': userobj.name,
        'name': userobj.fullname,
        'bio': userobj.about,
        'require_activation': 'false',
    }))


def sign(payload_b64):
    return hmac.new(sso_secret, payload_b64, hashlib.sha256)



#new user registration
import logging

from pylons import config
from paste.deploy.converters import asbool
from six import text_type

import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.authz as authz
import ckan.logic as logic
import ckan.logic.schema as schema
import ckan.lib.captcha as captcha
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.lib.authenticator as authenticator
import ckan.plugins as p

from ckan.common import _, c, request, response

log = logging.getLogger(__name__)


abort = base.abort
render = base.render

check_access = logic.check_access
get_action = logic.get_action
NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
ValidationError = logic.ValidationError
UsernamePasswordError = logic.UsernamePasswordError

DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten




def set_repoze_user(user_id):
    '''Set the repoze.who cookie to match a given user_id'''
    if 'repoze.who.plugins' in request.environ:
        rememberer = request.environ['repoze.who.plugins']['friendlyform']
        identity = {'repoze.who.userid': user_id}
        response.headerlist += rememberer.remember(request.environ,
                                                   identity)

class UserNewController(base.BaseController):
    def __before__(self, action, **env):
        base.BaseController.__before__(self, action, **env)
        try:
            context = {'model': model, 'user': c.user,
                       'auth_user_obj': c.userobj}
            check_access('site_read', context)
        except NotAuthorized:
            if c.action not in ('login', 'request_reset', 'perform_reset',):
                abort(403, _('Not authorized to see this page'))

    # hooks for subclasses
    new_user_form = 'user/new_user_form.html'
    edit_user_form = 'user/edit_user_form.html'

    def _new_form_to_db_schema(self):
        return schema.user_new_form_schema()

    def _db_to_new_form_schema(self):
        '''This is an interface to manipulate data from the database
        into a format suitable for the form (optional)'''

    def _edit_form_to_db_schema(self):
        return schema.user_edit_form_schema()

    def _db_to_edit_form_schema(self):
        '''This is an interface to manipulate data from the database
        into a format suitable for the form (optional)'''

    def _setup_template_variables(self, context, data_dict):
        c.is_sysadmin = authz.is_sysadmin(c.user)
        try:
            user_dict = get_action('user_show')(context, data_dict)
        except NotFound:
            h.flash_error(_('Not authorized to see this page'))
            h.redirect_to(controller='user', action='login')
        except NotAuthorized:
            abort(403, _('Not authorized to see this page'))

        c.user_dict = user_dict
        c.is_myself = user_dict['name'] == c.user
        c.about_formatted = h.render_markdown(user_dict['about'])

    # end hooks

    def _get_repoze_handler(self, handler_name):
        '''Returns the URL that repoze.who will respond to and perform a
        login or logout.'''
        return getattr(request.environ['repoze.who.plugins']['friendlyform'],
                       handler_name)

    def index(self):
        page = h.get_page_number(request.params)
        c.q = request.params.get('q', '')
        c.order_by = request.params.get('order_by', 'name')

        context = {'return_query': True, 'user': c.user,
                   'auth_user_obj': c.userobj}

        data_dict = {'q': c.q,
                     'order_by': c.order_by}

        limit = int(
            request.params.get('limit', config.get('ckan.user_list_limit', 20))
        )
        try:
            check_access('user_list', context, data_dict)
        except NotAuthorized:
            abort(403, _('Not authorized to see this page'))

        users_list = get_action('user_list')(context, data_dict)

        c.page = h.Page(
            collection=users_list,
            page=page,
            url=h.pager_url,
            item_count=users_list.count(),
            items_per_page=limit
        )
        return render('user/list.html')

    def read(self, id=None):
        context = {'model': model, 'session': model.Session,
                   'user': c.user, 'auth_user_obj': c.userobj,
                   'for_view': True}
        data_dict = {'id': id,
                     'user_obj': c.userobj,
                     'include_datasets': True,
                     'include_num_followers': True}

        self._setup_template_variables(context, data_dict)

        # The legacy templates have the user's activity stream on the user
        # profile page, new templates do not.
        if asbool(config.get('ckan.legacy_templates', False)):
            c.user_activity_stream = get_action('user_activity_list_html')(
                context, {'id': c.user_dict['id']})

        return render('user/read.html')

    def me(self, locale=None):
        if not c.user:
            h.redirect_to(locale=locale, controller='user', action='login',
                          id=None)
        user_ref = c.userobj.get_reference_preferred_for_uri()
        h.redirect_to(locale=locale, controller='user', action='dashboard')

    def register(self, data=None, errors=None, error_summary=None):
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        print ('test0')
        try:
            check_access('user_create', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to register as a user.'))

        return self.new(data, errors, error_summary)

    def new(self, data=None, errors=None, error_summary=None):
        '''GET to display a form for registering a new user.
           or POST the form data to actually do the user registration.
        '''
        context = {'model': model,
                   'session': model.Session,
                   'user': c.user,
                   'auth_user_obj': c.userobj,
                   'schema': self._new_form_to_db_schema(),
                   'save': 'save' in request.params}
	print ('test1')
        try:
            check_access('user_create', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to create a user'))

        if context['save'] and not data and request.method == 'POST':
            return self._save_new(context)

        if c.user and not data and not authz.is_sysadmin(c.user):
            # #1799 Don't offer the registration form if already logged in
            return render('user/logout_first.html')

        data = data or {}
        errors = errors or {}
        error_summary = error_summary or {}
        vars = {'data': data, 'errors': errors, 'error_summary': error_summary}

        c.is_sysadmin = authz.is_sysadmin(c.user)
        c.form = render(self.new_user_form, extra_vars=vars)
        return render('user/new.html')

    def delete(self, id):
        '''Delete user with id passed as parameter'''
        context = {'model': model,
                   'session': model.Session,
                   'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': id}

        try:
            get_action('user_delete')(context, data_dict)
            user_index = h.url_for(controller='user', action='index')
            h.redirect_to(user_index)
        except NotAuthorized:
            msg = _('Unauthorized to delete user with id "{user_id}".')
            abort(403, msg.format(user_id=id))

    def generate_apikey(self, id):
        '''Cycle the API key of a user'''
        context = {'model': model,
                   'session': model.Session,
                   'user': c.user,
                   'auth_user_obj': c.userobj,
                   }
        if id is None:
            if c.userobj:
                id = c.userobj.id
            else:
                abort(400, _('No user specified'))
        data_dict = {'id': id}

        try:
            result = get_action('user_generate_apikey')(context, data_dict)
        except NotAuthorized:
            abort(403, _('Unauthorized to edit user %s') % '')
        except NotFound:
            abort(404, _('User not found'))

        h.flash_success(_('Profile updated'))
        h.redirect_to(controller='user', action='read', id=result['name'])

    def _save_new(self, context):
        print ('test2')
        came_from = request.params.get('came_from', '')
        sig =  request.params.get('sig', '')
        redirect_url = came_from + '&sig=' + sig if came_from != '' else ''
        print (redirect_url)
        try:
            data_dict = logic.clean_dict(unflatten(
                logic.tuplize_dict(logic.parse_params(request.params))))
            context['message'] = data_dict.get('log_message', '')
            captcha.check_recaptcha(request)
            user = get_action('user_create')(context, data_dict)
        except NotAuthorized:
            abort(403, _('Unauthorized to create user %s') % '')
        except NotFound as e:
            abort(404, _('User not found'))
        except DataError:
            abort(400, _(u'Integrity Error'))
        except captcha.CaptchaError:
            error_msg = _(u'Bad Captcha. Please try again.')
            h.flash_error(error_msg)
            return self.new(data_dict)
        except ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.new(data_dict, errors, error_summary)
        if not c.user:
            # log the user in programatically
            set_repoze_user(data_dict['name'])
            if redirect_url == '':
                h.redirect_to(controller='user', action='me')
            else: 
                h.redirect_to(redirect_url)
        else:
            # #1799 User has managed to register whilst logged in - warn user
            # they are not re-logged in as new user.
            h.flash_success(_('User "%s" is now registered but you are still '
                            'logged in as "%s" from before') %
                            (data_dict['name'], c.user))
            if authz.is_sysadmin(c.user):
                # the sysadmin created a new user. We redirect him to the
                # activity page for the newly created user
                h.redirect_to(controller='user',
                              action='activity',
                              id=data_dict['name'])
            else:
                return render('user/logout_first.html')


