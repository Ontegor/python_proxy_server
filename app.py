#!/usr/bin/python

host_name = ""

host_scheme = "https"

encrypted_connection = 1

proxy_host_name = ''

subdomain = ''

# -----------------------------------------------------------------------------
# Удаляемые из ответа сервера заголовки. Указываются в нижнем регистре.

skip_headers = [
  "content-security-policy",
  "x-content-security-policy",
  "content-security-policy-report-only",
  "x-content-security-policy-report-only",
  "x-webkit-csp",
  "x-webkit-csp-report-only",
  "public-key-pins",
  "public-key-pins-report-only"]



from flask import Flask, redirect
from flask import request
from flask import Response
import urllib.parse
import re
import urllib3

app = Flask(__name__)
# app.debug = True
# app.secret_key = 'development key'

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    response = Response('')

#     if encrypted_connection and 'https' != request.scheme:
#       resp.headers['Strict-Transport-Security'] =  'max-age=31536000'
#       redirect ('https://' + request.host + request.path, code = 307)
#       return
#
#     elif not encrypted_connection and 'http' != request.scheme:
#       resp.headers['Strict-Transport-Security'] =  'max-age=0'
#       redirect('http://' + request.host + request.path, code = 307)
#       return


    subdomain = ''

    path = request.path
    path_parts = request.path.split('/', 2)
    if len(path_parts[1]) > 2 and '.' == path_parts[1][0] and '.' == path_parts[1][-1]:
        subdomain = path_parts[1][1:]
        path = '/'
        if len(path_parts) > 2:
          path += path_parts[2]
    else:
        host_parts = request.host.split('.')
        if len(host_parts) > 3:
            subdomain = '.'.join(host_parts[0:-3]) + '.'

#     if 'info_hash' in request.GET and \
#            'peer_id' in request.GET and \
#            'port' in request.GET and \
#            not 'ip' in request.GET:
#            path_qs += urllib.quote(request.remote_addr)

    url = host_scheme + '://' + host_name + path

#     print(url)

    headers = {}
    for name, value in request.headers.items():
        if not name.startswith('X-'):
            headers[name] = value.replace(proxy_host_name, host_name)
    headers['Accept-Encoding'] = 'deflate'
    headers['Proxy-Agent'] = 'zazure'

    # send req to host
    http = urllib3.PoolManager()
    try:
       result = http.request(
            request.method,
            url,
            fields          = request.data,
            headers          = headers,
            retries = False
          )
    except Exception as e:
          response.status_int = 504
          response.data = str(e)
          return response


    if result.status < 512:
          response.status_int = result.status
    else: # fix cloudflare codes
         response.status_int = 503

    content = result.data
    response.headers = {}
    content_type  = '??'

    for name, value in result.headers.items():
          name_l = name.lower()
          value = value.strip()
          if name_l in skip_headers:
            continue
          if 'content-type' == name_l:
            content_type = re.split(r'[:;\s\/\\=]+', value.lower(), 2)
          else:
            value = value.replace(host_name, proxy_host_name)
          response.headers[name] = value

    if  result.status in [301, 302, 303, 307] and result.headers.get('Location') != None:
        return redirect (response.headers.get('Location'), code = result.status)

    if content_type[0] in ['text', 'application']:
          if content_type[1] in ['html', 'xhtml+xml']:
            content = modify_content(content, mode = 'html')
          elif content_type[1] in ['xml']:
            content = modify_content(content, mode = 'xml')
          elif content_type[1] in ['css']:
            content = modify_content(content, mode = 'css')
          elif content_type[1] in ['javascript', 'x-javascript']:
            content = modify_content(content)

    response.data = content
    return response

def modify_content(content, mode = None):
    def dashrepl(matchobj):
      if mode == 'xml':
        result = ''
        subdomain = matchobj.group(2)
      else:
        result = matchobj.group(1)
        subdomain = matchobj.group(4)

      if encrypted_connection:
        result += 'https://' + proxy_host_name
        if subdomain:
          result += '/.' + subdomain
      else:
        result += 'http://' + subdomain + proxy_host_name
      return result

    if mode == 'css':
      regexp = r'((url)\s*\(\s*[\'"]?)(https?:|)\/\/'
    elif mode == 'html':
      regexp = r'(\<[^\<\>]+\s(src|href|action)=[\'"]?)(https?:|)\/\/'
    elif mode == 'xml':
      regexp = r'(https?:|)\/\/'
    else:
      regexp = r'(())(https?:)\/\/'
    regexp += r'([a-z0-9][-a-z0-9\.]*\.|)'
    regexp += re.escape(host_name)

    content = content.decode('utf-8')

    return re.sub(regexp, dashrepl, content, flags = re.IGNORECASE)
