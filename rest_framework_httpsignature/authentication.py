import re
from rest_framework import authentication
from rest_framework import exceptions
from httpsig import HeaderSigner
from httpsig.utils import HASHES, CaseInsensitiveDict, generate_message
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


class SignatureAuthentication(authentication.BaseAuthentication):

    SIGNATURE_RE = re.compile('signature="(.+?)"')
    SIGNATURE_HEADERS_RE = re.compile('headers="([\(\)\sa-z0-9-]+?)"')

    API_KEY_HEADER = 'X-Api-Key'
    ALGORITHM = 'hmac-sha256'

    def __init__(self):
        self._sign_algorithm, self._hash_algorithm = self.ALGORITHM.split('-')
        self._hash = HASHES[self._hash_algorithm]

    def _verify_rsa(self, request, headers_dict, api_key, sent_signature):

        headers = CaseInsensitiveDict(headers_dict)

        host = request.META.get(self.header_canonical('Host'))
        method = request.method
        path = request.path

        rsa_key = RSA.importKey(api_key)
        self._rsa = PKCS1_v1_5.new(rsa_key)

        signable = generate_message(headers_dict, headers, host, method, path)
        mhash = self._hash.new()
        mhash.update(signable)

        return self._rsa.verify(mhash, sent_signature)

    def _verify_hmac(self, request, sent_signature, api_key, secret):
        # Build string to sign from "headers" part of Signature value.
        computed_string = self.build_signature(api_key, secret, request)
        computed_signature = self.get_signature_from_signature_string(
            computed_string)

        if computed_signature != sent_signature:
            raise exceptions.AuthenticationFailed('Bad signature')

    def _verify(self, request, api_key, secret):

        # Check if request has a "Signature" request header.
        authorization_header = self.header_canonical('Authorization')
        sent_string = request.META.get(authorization_header)
        if not sent_string:
            raise exceptions.AuthenticationFailed('No signature provided')

        sent_signature = self.get_signature_from_signature_string(sent_string)

        signature_headers = self.get_headers_from_signature(sent_signature)
        headers_dict = self.build_headers_dict(request, signature_headers)

        verified = False

        if self._sign_algorithm == 'rsa':
            verified = self._verify_rsa(request, headers_dict, api_key, sent_signature)
        elif self._sign_algorithm == 'hmac':
            verified = self._verify_hmac(request, sent_signature, api_key, secret)
        if not verified:
            raise SystemError('No valid encryptor found.')
        return verified

    def get_signature_from_signature_string(self, signature):
        """Return the signature from the signature header or None."""
        match = self.SIGNATURE_RE.search(signature)
        if not match:
            return None
        return match.group(1)

    def get_headers_from_signature(self, signature):
        """Returns a list of headers fields to sign.

        According to http://tools.ietf.org/html/draft-cavage-http-signatures-03
        section 2.1.3, the headers are optional. If not specified, the single
        value of "Date" must be used.
        """
        match = self.SIGNATURE_HEADERS_RE.search(signature)
        if not match:
            return ['date']
        headers_string = match.group(1)
        return headers_string.split()

    def header_canonical(self, header_name):
        """Translate HTTP headers to Django header names."""
        # Translate as stated in the docs:
        # https://docs.djangoproject.com/en/1.6/ref/request-response/#django.http.HttpRequest.META
        header_name = header_name.lower()
        if header_name == 'content-type':
            return 'CONTENT-TYPE'
        elif header_name == 'content-length':
            return 'CONTENT-LENGTH'
        return 'HTTP_%s' % header_name.replace('-', '_').upper()

    def build_headers_dict(self, request, signature_headers):
        """Build a dict with headers and values used in the signature.

        "signature_headers" is a list of lowercase header names.
        """
        d = {}
        for header in signature_headers:
            if header == '(request-target)':
                continue
            d[header] = request.META.get(self.header_canonical(header))
        return d

    def build_signature(self, user_api_key, user_secret, request):
        """Return the signature for the request."""
        path = request.get_full_path()
        sent_signature = request.META.get(
            self.header_canonical('Authorization'))
        signature_headers = self.get_headers_from_signature(sent_signature)
        unsigned = self.build_headers_dict(request, signature_headers)

        # Sign string and compare.
        signer = HeaderSigner(
            key_id=user_api_key, secret=user_secret,
            headers=signature_headers, algorithm=self.ALGORITHM)
        signed = signer.sign(unsigned, method=request.method, path=path)
        return signed['authorization']

    def fetch_user_data(self, api_key):
        """Retuns (User instance, API Secret) or None if api_key is bad."""
        return None

    def authenticate(self, request):
        # Check for API key header.
        api_key_header = self.header_canonical(self.API_KEY_HEADER)
        api_key = request.META.get(api_key_header)
        if not api_key:
            return None

        # Fetch credentials for API key from the data store.
        try:
            user, secret = self.fetch_user_data(api_key)
        except TypeError:
            raise exceptions.AuthenticationFailed('Bad API key')

        self._verify(request, api_key, secret)

        return (user, api_key)
