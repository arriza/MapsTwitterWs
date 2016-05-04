from webapp2_extras import sessions
from google.appengine.api import users
import webapp2
import jinja2
import os
import logging
import httplib2
import urllib
import random
import time
import hmac
import binascii
import hashlib

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

consumer_key = 'BVz3sbpRsYhtGRcHBZxOyqnMN'
consumer_secret = 'FizZNzJF2kKZRbAjhVJ1XxZOyWwzPAaIjVTztOkbCGLDxQftpG'
oauth_token = ''
oauth_token_secret = ''


class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()


config = {}
config['webapp2_extras.sessions'] = {'secret_key': 'my-super-secret-key'}


class MainHandler(BaseHandler):
    def get(self):
        logging.debug('ENTERING MainHandler --->')
        self.response.write('<a href="/LoginAndAuthorize">Login and Authorize with TWITTER</a>')


class LoginAndAuthorize(BaseHandler):
    def get(self):
        callback_uri = 'http://mapstwitterws.appspot.com/callback_uri'
        logging.debug('ENTERING LoginAndAuthorize --->')
        http = httplib2.Http()
        method = 'POST'
        url = 'https://api.twitter.com/oauth/request_token'
        oauth_headers = {'oauth_callback': callback_uri}
        goiburuak = {'User-Agent': 'MapsTwitterWs',
                     'Authorization': createAuthHeader(method, url, oauth_headers, None, None)}
        erantzuna, content = http.request(url, method, headers=goiburuak)
        if erantzuna['status'] != '200':
            logging.debug('/oauth/request_token != 200')
            return
        logging.debug(content)
        oauth_split = content.split('&')[0]
        oauth_split = oauth_split.split('=')[1]
        secret_split = content.split('&')[1]
        secret_split = secret_split.split('=')[1]
        confirmed_split = content.split('&')[2]
        confirmed_split = confirmed_split.split('=')[1]
        if 'false' in confirmed_split:
            logging.debug('Errore bat dago.')
            return
        self.session['oauth_token'] = oauth_split
        self.redirect('https://api.twitter.com/oauth/authenticate?' + urllib.urlencode({'oauth_token': oauth_split}))


class twitter(BaseHandler):
    def get(self):
        logging.debug('Txandapasa')
        oauth_verifier = self.request.get('oauth_verifier')
        logging.debug(oauth_verifier)
        metodoa = 'POST'
        uri = '/oauth/access_token'
        zerbitzaria = 'api.twitter.com'
        oauth_headers = {'oauth_token':self.session.get('oauth_token')}
        params = {'oauth_verifier' : oauth_verifier}
        edukia = urllib.urlencode(params)
        goiburuak = {'User-Agent' : 'MapsTwitterWs',
                     'Host' : zerbitzaria,
                     'Content-Type' : 'application/x-www-form-urlencoded',
                     'Accept' : '*/*',
                     'Content-Length': str(len(edukia)),
                     'Authorization':createAuthHeader(metodoa, uri, oauth_headers, params, self.session.get('oauth_token_secret'))}

        http = httplib2.Http()
        erantzuna, content = http.request('https://' + zerbitzaria + uri, method=metodoa, headers=goiburuak, body=edukia)
        self.response.write(erantzuna)
        self.response.write(content)
        logging.debug(erantzuna)
        logging.debug(content)

class mapa(BaseHandler):
    def get(self):
        template = JINJA_ENVIRONMENT.get_template('mapa.html')
        template_values = {}
        self.response.write(template.render(template_values))



def createAuthHeader(method, base_url, oauth_headers, request_params, oauth_token_secret):
    logging.debug('ENTERING createAuthHeader --->')
    oauth_headers.update({'oauth_consumer_key': consumer_key,
                          'oauth_nonce': str(random.randint(0, 999999999)),
                          'oauth_signature_method': "HMAC-SHA1",
                          'oauth_timestamp': str(int(time.time())),
                          'oauth_version': "1.0"})
    oauth_headers['oauth_signature'] = \
        urllib.quote(createRequestSignature(method, base_url, oauth_headers, request_params, oauth_token_secret), "")

    if oauth_headers.has_key('oauth_callback'):
        oauth_headers['oauth_callback'] = urllib.quote_plus(oauth_headers['oauth_callback'])
    authorization_header = "OAuth "
    for each in sorted(oauth_headers.keys()):
        if each == sorted(oauth_headers.keys())[-1]:
            authorization_header = authorization_header \
                                   + each + "=" + "\"" \
                                   + oauth_headers[each] + "\""
        else:
            authorization_header = authorization_header \
                                   + each + "=" + "\"" \
                                   + oauth_headers[each] + "\"" + ", "

    return authorization_header

def GetTimeLine(BaseHandler):
    def get(self):
        metodoa = 'GET'
        uri = '/1.1/statuses/user_timeline.json?screen_name=twitterapi&count=2'
        zerbitzaria = 'api.twitter.com'
        oauth_headers = {'oauth_token': self.session.get('oauth_token')}
        goiburuak = {'User-Agent': 'MapsTwitterWs',
                     'Host': zerbitzaria,
                     'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': '*/*',
                     'Authorization': createAuthHeader(metodoa, uri, oauth_headers,
                                                       self.session.get('oauth_token_secret'))}

        http = httplib2.Http()
        erantzuna, content = http.request('https://' + zerbitzaria + uri, method=metodoa, headers=goiburuak,
                                          body='')
        self.response.write(erantzuna)
        self.response.write(content)
        logging.debug(erantzuna)
        logging.debug(content)

def createRequestSignature(method, base_url, oauth_headers, request_params, oauth_token_secret):
    logging.debug('ENTERING createRequestSignature --->')
    encoded_params = ''
    params = {}
    params.update(oauth_headers)
    if request_params:
        params.update(request_params)
    for each in sorted(params.keys()):
        key = urllib.quote(each, "")
        value = urllib.quote(params[each], "")
        if each == sorted(params.keys())[-1]:
            encoded_params = encoded_params + key + "=" + value
        else:
            encoded_params = encoded_params + key + "=" + value + "&"

    signature_base = method.upper() + \
                     "&" + urllib.quote(base_url, "") + \
                     "&" + urllib.quote(encoded_params, "")

    signing_key = ''
    if oauth_token_secret == None:
        signing_key = urllib.quote(consumer_secret, "") + "&"
    else:
        signing_key = urllib.quote(consumer_secret, "") + "&" + urllib.quote(oauth_token_secret, "")

    hashed = hmac.new(signing_key, signature_base, hashlib.sha1)
    oauth_signature = binascii.b2a_base64(hashed.digest())

    return oauth_signature[:-1]


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/LoginAndAuthorize', LoginAndAuthorize),
    ('/callback_uri', twitter),
    ('/mapa', mapa),
    ('/timeline' , GetTimeLine)

], config=config, debug=True)
