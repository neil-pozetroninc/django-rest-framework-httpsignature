from django.utils.deprecation import MiddlewareMixin
from httpsig import utils
import time

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
    
try:
    import uhmac as hmac
except ImportError:
    import hmac


class HMACMiddleware(MiddlewareMixin):

    #def process_request(self, request):
        #return None

    #def process_view(self, request, callback, callback_args, callback_kwargs):
        #return None
    
    def process_response(self, request, response):
        """
        Add the headers
        """
        try:
            response['Timestamp'] = str(int(time.time()))
            hmac_instance = hmac.new(request.auth.encode('utf-8'), digestmod='sha256')
            authenticated = True
        except TypeError:
            # If the request doesn't have a valid auth (key) then we will get
            # TypeError: key: expected bytes or bytearray, but got 'NoneType'
            authenticated = False
        except AttributeError:
            # If the request doesn't have a valid keyId then we will get
            # AttributeError: 'WSGIRequest' object has no attribute 'auth'
            authenticated = False
        finally:
            if authenticated:
                signable_message = utils.generate_message(['timestamp'], {'timestamp': response['Timestamp']})
                signable_message = signable_message + response.content
                #print('Signable Message is: {}'.format(signable_message))
                hmac_instance.update(signable_message)
                response['Content-HMAC'] = '"{}"'.format(hmac_instance.hexdigest())
        return response
