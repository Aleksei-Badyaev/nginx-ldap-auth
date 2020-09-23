#!env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014-2015 Nginx, Inc.
"""Nginx LDAP Authentication."""

import sys
import os
import stat
import signal
import base64
import ldap
import argparse

from socketserver import ThreadingUnixStreamServer, ThreadingMixIn
from http.cookies import BaseCookie
from http.server import HTTPServer, BaseHTTPRequestHandler


Listen = '/tmp/nginx-ldap-auth.sock'


class AuthNetServer(ThreadingMixIn, HTTPServer):
    """Network TCP server."""


class AuthStreamServer(ThreadingUnixStreamServer, HTTPServer):
    """Unix socket server."""


class AuthHandler(BaseHTTPRequestHandler):
    """Обработчик запроса."""

    # Return True if request is processed and response sent, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def do_GET(self):
        """Выполнение метода GET."""
        ctx = self.ctx
        ctx['action'] = 'input parameters check'
        for k, v in list(self.get_params().items()):
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] == None:
                self.auth_failed(
                    ctx,
                    'required "%s" header was not passed' % k,
                )
                return True

        ctx['action'] = 'performing authorization'
        auth_header = self.headers.get('Authorization')
        auth_cookie = self.get_cookie(ctx['cookiename'])

        if auth_cookie != None and auth_cookie != '':
            auth_header = "Basic " + auth_cookie
            self.log_message(
                'using username/password from cookie %s',
                ctx['cookiename'],
            )
        else:
            self.log_message(
                'using username/password from authorization header'
            )

        if auth_header is None or not auth_header.lower().startswith('basic '):
            self.send_response(401)
            self.send_header(
                'WWW-Authenticate',
                'Basic realm="' + ctx['realm'] + '"',
            )
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            if auth_header is None:
                self.log_message('auth_header is None')
            else:
                self.log_message('auth_header: %s', auth_header)
            return True

        ctx['action'] = 'decoding credentials'
        try:
            auth_decoded = base64.b64decode(auth_header[6:])
            auth_decoded = auth_decoded.decode('utf-8')
            user, passwd = auth_decoded.split(':', 1)
        except Exception as ex:
            self.auth_failed(ctx)
            return True

        ctx['user'] = user
        ctx['pass'] = passwd
        # Continue request processing
        return False

    def get_cookie(self, name):
        """Get auth cookie."""
        cookies = self.headers.get('Cookie')
        if cookies:
            authcookie = BaseCookie(cookies).get(name)
            if authcookie:
                return authcookie.value
            else:
                return None
        else:
            return None


    def auth_failed(self, ctx, errmsg = None):
        """Log the error and complete the request with appropriate status."""
        msg = 'Error while ' + ctx['action']
        if errmsg:
            msg += ': ' + errmsg

        ex, value, trace = sys.exc_info()

        if ex != None:
            msg += ": " + str(value)

        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.log_error(msg)
        self.send_response(401)
        self.send_header(
            'WWW-Authenticate',
            'Basic realm="' + ctx['realm'] + '"',
        )
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

    def get_params(self):
        return {}

    def log_message(self, format, *args):
        """Output log message."""
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = '-'
        if not hasattr(self, 'ctx'):
            user = '-'
        else:
            user = self.ctx['user']
        sys.stdout.write(
            '%s - %s [%s] %s\n' % (
                addr,
                user,
                self.log_date_time_string(),
                format % args,
            ))

    def log_error(self, format, *args):
        """Output error message."""
        self.log_message(format, *args)


class LDAPAuthHandler(AuthHandler):
    """Verify username/password against LDAP server."""

    # Parameters to put into self.ctx from the HTTP header of auth request
    params =  {
             # parameter      header         default
             'realm': ('X-Ldap-Realm', 'Restricted'),
             'url': ('X-Ldap-URL', None),
             'starttls': ('X-Ldap-Starttls', 'false'),
             'disable_referrals': ('X-Ldap-DisableReferrals', 'false'),
             'basedn': ('X-Ldap-BaseDN', None),
             'template': ('X-Ldap-Template', '(cn=%(username)s)'),
             'binddn': ('X-Ldap-BindDN', ''),
             'bindpasswd': ('X-Ldap-BindPass', ''),
             'cookiename': ('X-CookieName', ''),
        }

    @classmethod
    def set_params(cls, params):
        cls.params = params

    def get_params(self):
        return self.params

    # GET handler for the authentication request
    def do_GET(self):
        """Handle GET request."""
        ctx = dict()
        self.ctx = ctx
        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'
        if AuthHandler.do_GET(self):
            # request already processed
            return

        ctx['action'] = 'empty password check'
        if not ctx['pass']:
            self.auth_failed(ctx, 'attempt to use empty password')
            return
        try:
            # check that uri and baseDn are set
            # either from cli or a request
            if not ctx['url']:
                self.log_message('LDAP URL is not set!')
                return
            if not ctx['basedn']:
                self.log_message('LDAP baseDN is not set!')
                return

            ctx['action'] = 'initializing LDAP connection'
            ldap_obj = ldap.initialize(ctx['url']);

            # Python-ldap module documentation advises to always
            # explicitely set the LDAP version to use after running
            # initialize() and recommends using LDAPv3. (LDAPv2 is
            # deprecated since 2003 as per RFC3494)
            #
            # Also, the STARTTLS extension requires the
            # use of LDAPv3 (RFC2830).
            ldap_obj.protocol_version=ldap.VERSION3

            # Establish a STARTTLS connection if required by the
            # headers.
            if ctx['starttls'] == 'true':
                ldap_obj.start_tls_s()

            # See https://www.python-ldap.org/en/latest/faq.html
            if ctx['disable_referrals'] == 'true':
                ldap_obj.set_option(ldap.OPT_REFERRALS, 0)

            ctx['action'] = 'binding as search user'
            ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            ctx['action'] = 'preparing search filter'
            searchfilter = ctx['template'] % { 'username': ctx['user'] }

            self.log_message(('searching on server "%s" with base dn ' + \
                              '"%s" with filter "%s"') %
                              (ctx['url'], ctx['basedn'], searchfilter))

            ctx['action'] = 'running search query'
            results = ldap_obj.search_s(
                base=ctx['basedn'],
                scope=ldap.SCOPE_SUBTREE,
                filterstr=searchfilter,
                attrlist=['objectclass'],
                attrsonly=1,
            )
            ctx['action'] = 'verifying search query results'
            nres = len(results)

            if nres < 1:
                self.auth_failed(ctx, 'no objects found')
                return

            if nres > 1:
                self.log_message(
                    'note: filter match multiple objects: %d, using first',
                    nres,
                )
            user_entry = results[0]
            ldap_dn = user_entry[0]
            if ldap_dn == None:
                self.auth_failed(ctx, 'matched object has no dn')
                return
            self.log_message('attempting to bind using dn "%s"' % (ldap_dn))
            ctx['action'] = 'binding as an existing user "%s"' % ldap_dn
            ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)
            self.log_message('Auth OK for user "%s"' % (ctx['user']))

            # Successfully authenticated user
            self.send_response(200)
            self.send_header('X-Remote-User', ctx['user'])
            self.end_headers()

        except Exception as ex:
            self.auth_failed(ctx)

def exit_handler(signal, frame):
    """Exit from service."""
    global Listen

    if isinstance(Listen, str):
        try:
            os.unlink(Listen)
        except:
            ex, value, trace = sys.exc_info()
            sys.stderr.write('Failed to remove socket "%s": %s\n' %
                             (Listen, str(value)))
            sys.stderr.flush()
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('--host',  metavar="hostname",
        help="host to bind (Default: /tmp/nginx-ldap-auth.sock)")
    group.add_argument('-p', '--port', metavar="port", type=int,
        help="port to bind")
    # ldap options:
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-u', '--url', metavar="URL",
        default="ldap://localhost:389",
        help=("LDAP URI to query (Default: ldap://localhost:389)"))
    group.add_argument('-s', '--starttls', metavar="starttls",
        default="false",
        help=("Establish a STARTTLS protected session (Default: false)"))
    group.add_argument('--disable-referrals', metavar="disable_referrals",
        default="false",
        help=("Sets ldap.OPT_REFERRALS to zero (Default: false)"))
    group.add_argument('-b', metavar="baseDn", dest="basedn", default='',
        help="LDAP base dn (Default: unset)")
    group.add_argument('-D', metavar="bindDn", dest="binddn", default='',
        help="LDAP bind DN (Default: anonymous)")
    group.add_argument('-w', metavar="passwd", dest="bindpw", default='',
        help="LDAP password for the bind DN (Default: unset)")
    group.add_argument('-f', '--filter', metavar='filter',
        default='(cn=%(username)s)',
        help="LDAP filter (Default: cn=%%(username)s)")
    # http options:
    group = parser.add_argument_group(title="HTTP options")
    group.add_argument('-R', '--realm', metavar='"Restricted Area"',
        default="Restricted", help='HTTP auth realm (Default: "Restricted")')
    group.add_argument('-c', '--cookie', metavar="cookiename",
        default="", help="HTTP cookie name to set in (Default: unset)")

    args = parser.parse_args()
    if args.host:
        if args.host[:1] == '/':
            Listen = args.host
        else:
            Listen = (args.host, args.port)
    auth_params = {
             'realm': ('X-Ldap-Realm', args.realm),
             'url': ('X-Ldap-URL', args.url),
             'starttls': ('X-Ldap-Starttls', args.starttls),
             'disable_referrals': ('X-Ldap-DisableReferrals', args.disable_referrals),
             'basedn': ('X-Ldap-BaseDN', args.basedn),
             'template': ('X-Ldap-Template', args.filter),
             'binddn': ('X-Ldap-BindDN', args.binddn),
             'bindpasswd': ('X-Ldap-BindPass', args.bindpw),
             'cookiename': ('X-CookieName', args.cookie),
    }
    LDAPAuthHandler.set_params(auth_params)
    server = None
    if isinstance(Listen, str):
        server = AuthStreamServer(Listen, LDAPAuthHandler)
    else:
        server = AuthNetServer(Listen, LDAPAuthHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    if isinstance(Listen, str):
        os.chmod(Listen, (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                          stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                          stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
    sys.stdout.write('Start listening on {}...\n'.format(Listen))
    sys.stdout.flush()
    server.serve_forever()
