from django import http
from django.utils.deprecation import MiddlewareMixin
from httpsig import utils
from time import gmtime

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
    
try:
    import uhmac as hmac
except ImportError:
    import hmac

def httpdate(dt):
    """Return a string representation of a date according to RFC 1123
    (HTTP/1.1).

    The supplied date must be in UTC.

    """
    dt_year, dt_month, dt_day, dt_hour, dt_minute, dt_second, dt_weekday, dt_y = dt
    del(dt)
    weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt_weekday]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
             "Oct", "Nov", "Dec"][dt_month - 1]
    return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (weekday, dt_day, month,
        dt_year, dt_hour, dt_minute, dt_second)

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
                signable_message = utils.generate_message(['date'], {'date':httpdate(gmtime()[:-1:])})
                signable_message = signable_message + response.content
                #print('Signable Message is: {}'.format(signable_message))
                hmac_instance.update(signable_message)
                response['Content-HMAC'] = '"{}"'.format(hmac_instance.hexdigest())
        return response