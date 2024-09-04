import subprocess
import requests
import re
from bs4 import BeautifulSoup as bs
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import urllib.parse
import termcolor

def banner():
        print(termcolor.colored("""
   ___   ___  ____  _   __     __       ____                          
  / _ | / _ \/  _/ | | / /_ __/ /__    / __/______ ____  ___  ___ ____
 / __ |/ ___// /   | |/ / // / / _ \  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
/_/ |_/_/  /___/   |___/\_,_/_/_//_/ /___/\__/\_,_/_//_/_//_/\__/_/ 
                                Author:- Rituraj Dubey    
          """, 'red', attrs=['bold']))
        
def color(obj, color):
    return termcolor.colored((obj), color=color)

def run_proxy(target_domain):
    if target_domain.startswith('http://'):
        target_domain = target_domain.replace('http://',"")
    if target_domain.startswith('https://'):
        target_domain = target_domain.replace('https://',"")
    try:
        subprocess.run(["mitmproxy", "-s", "proxy.py", "--set", f"target_domain={target_domain}"])
    except KeyboardInterrupt:
        print(termcolor.colored(("\n\nExiting Proxy..."), 'green'))

def parse_json(object): # Match JSON object from a respose
    json_pattern = re.compile(r'{.*}')
    json_match = json_pattern.search(object)
    if json_match:
        json_str = json_match.group()
        return json_str

def modify_json(json_data, param, payload): # Modify JSON as per Payload
    try:
        json_data = json_data
        json_keys = [i for i in json_data.keys()]
        json_data[json_keys[param-1]] = payload
        new_json_str = json.dumps(json_data)
        return new_json_str
    except json.JSONDecodeError as e:
        print("Error decoding JSON:", e)

def get_modified_data(data, param, payload): # Modify xxx-form-urlencoded with param index
    key_value_pairs = data.split('&')
    key_value_dict = dict(pair.split('=') for pair in key_value_pairs)
    injected_key = list(key_value_dict.keys())[param-1]
    key_value_dict[injected_key] = payload
    updated_data = '&'.join([f'{key}={value}' for key, value in key_value_dict.items()])
    return updated_data

def get_modified_data_param(data, param, payload): # Modify xxx-form-urlencoded with given param
    key_value_pairs = data.split('&')
    key_value_dict = dict(pair.split('=') for pair in key_value_pairs)
    key_value_dict[param] = payload
    updated_data = '&'.join([f'{key}={value}' for key, value in key_value_dict.items()])
    return updated_data 

def url_encode_string(input_string): # URL encodes SQLi Payloads
    encoded_string = urllib.parse.quote(input_string)
    return encoded_string

# Parse request headers in the requests.log file
def parse_headers(header_str): # Helper function for -- parse_request_logs()
    # Use regex to find tuples
    header_tuples = re.findall(r"\((b'[^']+'), (b'[^']+')\)", header_str)
    headers_dict = {}
    for key, value in header_tuples:
        headers_dict[key.strip("b'").encode().decode('unicode_escape')] = value.strip("b'").encode().decode('unicode_escape')
    return headers_dict

# Extract All Endpoints, Method Supported, Headers, Body from requests.log
def parse_request_logs():
    with open('requests.log', 'r') as log:
        log_content = log.read()
    request_pattern = re.compile(r"Request: (\w+) (.+)")
    header_pattern = re.compile(r"Headers: Headers\[(.+?)\]", re.DOTALL)
    header_pattern2 = re.compile(r"Header: Headers\[(.+)\]", re.DOTALL)
    content_pattern = re.compile(r"Content: b'(.+)'", re.DOTALL)
    requests = log_content.split("\n\n")
    api_endpoints = []
    for req in requests:
        req_method_url = request_pattern.search(req)
        headers = header_pattern.search(req)
        headers2 = header_pattern2.search(req)
        content = content_pattern.search(req)
        
        if req_method_url:
            method = req_method_url.group(1)
            url = req_method_url.group(2)
            
            headers_dict = {}
            if headers:
                headers_dict = parse_headers(headers.group(1))
            if headers2:
                headers_dict = parse_headers(headers2.group(1))
            
            body = ""
            if content:
                body = content.group(1)
            
            api_endpoints.append({
                "method": method,
                "url": url,
                "headers": headers_dict,
                "body": body
            })
    return api_endpoints

def is_query_endpoint(url): # Helper Function for --BOLA
    parsed_url = urlparse(url)
    return bool(parse_qs(parsed_url.query))

def has_url_query_parameter(url): # Helper Function for --SSRF
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    for param, values in query_params.items():
        for value in values:
            parsed_value = urllib.parse.urlparse(value)
            if parsed_value.scheme and parsed_value.netloc:
                return True,param
    return False

def extract_param_and_value(url): # Helper Function for --BOLA
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if query_params:
        param_name = list(query_params.keys())[0]
        param_value = query_params[param_name][0]
        return param_name, param_value
    return None, None

def test_broken_object_level_authorization(): # BOLA
    session = requests.Session()
    vulnerable_endpoints = []
    print(color("\n[*] Testing Broken Object Level Authorization (BOLA)", 'blue'))
    for endpoint in all_endpoints:
        if endpoint['method']=='GET' and is_query_endpoint(endpoint['url']):
            param_name, param_value = extract_param_and_value(endpoint['url'])
            if not param_name or not param_value.isdigit():
                continue
            base_value = int(param_value)
            test_values = [base_value + 1, base_value - 1]
            for value in test_values:
                params = {param_name: value}
                parsed_url = urlparse(endpoint['url'])
                new_query = urlencode(params)
                new_url = urlunparse(parsed_url._replace(query=new_query))
                response = session.get(new_url)
                if response.status_code == 200:
                    print(f"\n[+] Potential BOLA vulnerability found: {new_url}")
                    vulnerable_endpoints.append(new_url)
    if len(vulnerable_endpoints)>0:
        print(color(f"[+] BOLA Vulnerability Detected at {vulnerable_endpoints}", 'geen'))
    print("[-] BOLA Vulnerability Not Detected")

def test_broken_user_authentication():
    print(color("\n[*] Testing Broken User Authentication Vulnearbility (BUA)", 'blue')) # BUA
    with open('sqli_payloads.txt', 'r') as f:
        sqli_payloads = f.readlines()
    login_api= enum_post_endpoints()
    test_sqli(sqli_payloads, login_api)

def enum_post_endpoints(): # Helper Function for --BUA
    login_api = []
    for endpoint in all_endpoints:
        if endpoint['method']=='POST':
            if "login" in endpoint['url'].lower():
                for header in endpoint['headers'].keys():
                    if header=="Content-Type":
                        if "application/json" in endpoint['headers']['Content-Type']:
                            print(color(f"[+] Potential Login API Endpoint Found at {endpoint['url']}", 'yellow'))
                            login_api.append(endpoint)
                        elif "application/x-www-form-urlencoded" in endpoint['headers']['Content-Type']:
                            print(color(f"[+] Potential Login API Endpoint Found at {endpoint['url']}", 'yellow'))
                            login_api.append(endpoint)
            else:
                continue
        else:
            continue
    return login_api

def test_sqli(sqli_payloads, login_api): # Helper Function for --BUA
    session = requests.Session()
    for endpoint in login_api:
        if "application/json" in endpoint['headers']['Content-Type']:
            json_str = parse_json(endpoint['body'])
            json_data = json.loads(json_str)
            json_keys = [i for i in json_data.keys()]
            print(f"\n Which Parameter to test SQLi? ")
            key_count=0
            for i in json_keys:
                key_count+=1
                print(f"{key_count} {i}")
            param = int(input("\n Enter the choise : "))
            for payload in sqli_payloads:
                payload = payload.replace("\n","")
                new_data = modify_json(json_data,param,payload)
                response = session.post(endpoint['url'],json=new_data, headers=endpoint['headers'], allow_redirects=False)
                print(f"[*] Testing SQLi on {endpoint['url']} with payload: {payload} - Status Code: {response.status_code}")
                if response.status_code == 200:
                    for i in response.headers.keys():
                        if i=='Content-Type':
                            if 'application/json' in response.headers.get('Content-Type'):
                                try:
                                    resp_json = parse_json(response)
                                    resp_json_data = json.loads(resp_json)
                                    resp_json_keys = [i for i in resp_json_data.keys()]
                                    if "authenticated" in resp_json_keys:
                                        if resp_json_data['authenticated']=='true':
                                            print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                            print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                            return
                                    elif "login" in resp_json_keys:
                                        if resp_json_data['login']=='success':
                                            print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                            print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                            return
                                except:
                                    continue
                if response.status_code == 302:
                    try:
                        sqli_token = session.cookies.get_dict()
                        for g in response.headers.keys():
                            if g=="Cookie":
                                if sqli_token==response.cookies.get_dict():
                                    print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                    print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                    return
                            elif g=='Set-Cookie':
                                if sqli_token==response.cookies.get_dict():
                                    print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                    print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                    return
                            else:
                                continue
                    except:
                        continue
        if "application/x-www-form-urlencoded" in endpoint['headers']['Content-Type']:
            data = endpoint['body']
            key_value_pairs = data.split('&')
            key_value_dict = dict(pair.split('=') for pair in key_value_pairs)
            print(f"\n Which Parameter to test SQLi? ")
            key_count=0
            for i in list(key_value_dict.keys()):
                key_count+=1
                print(f"{key_count} {i}")
            param = int(input("\n Enter the choise : "))
            for payload in sqli_payloads:
                payload = payload.replace("\n","")
                payload = url_encode_string(payload)
                sqli_data = get_modified_data(endpoint['body'], param, payload)
                response = session.post(f"{endpoint['url']}", data=sqli_data, headers=endpoint['headers'], allow_redirects=False)
                print(f"[*] Testing SQLi on {endpoint['url']} with payload: {payload} - Status Code: {response.status_code}")
                if response.status_code == 200:
                    for i in response.headers.keys():
                        if i=='Content-Type':
                            if 'application/json' in response.headers.get('Content-Type'):
                                    try:
                                        resp_json = parse_json(response)
                                        resp_json_data = json.loads(resp_json)
                                        resp_json_keys = [i for i in resp_json_data.keys()]
                                        if "authenticated" in resp_json_keys:
                                            if resp_json_data['authenticated']=='true':
                                                print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                                print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                                return
                                        elif "login" in resp_json_keys:
                                            if resp_json_data['login']=='success':
                                                print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                                print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                                return
                                    except:
                                        continue
                if response.status_code == 302:
                    try:
                        sqli_token = session.cookies.get_dict()
                        for g in response.headers.keys():
                            if g=="Cookie":
                                if sqli_token==response.cookies.get_dict():
                                    print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                    print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                    return
                            elif g=='Set-Cookie':
                                if sqli_token==response.cookies.get_dict():
                                    print(color(f"[+] SQLi Detected at {endpoint['url']}", 'magenta'))
                                    print(color(f"[+] Possible BUA vulnerability at {endpoint['url']} with payload: {list(key_value_dict.keys())[param-1]}={payload}", 'green'))
                                    return
                            else:
                                continue
                    except:
                        continue
            else:
                continue
    print("[-] BUA Vulnerability NOT Detected")

def test_excessive_data_exposure(): # Excessive Data Exposure
    print(color("\n[*] Testing Excessive Data Exposure", 'blue'))
    session = requests.Session()
    flag = False
    for endpoint in all_endpoints:
        if endpoint['method']=='GET':
            response = session.get(f"{endpoint['url']}", headers=endpoint['headers'])
            if response.status_code == 200:
                for g in response.headers.keys():
                    if g=='Content-Type':
                        if 'application/json' in response.headers.get('Content-Type'):
                                try:
                                    resp_json = parse_json(response)
                                    resp_json_data = json.loads(resp_json)
                                    resp_json_keys = [i for i in resp_json_data.keys()]
                                    sensitive_keys = ["password", "ssn", "credit card",'email','account', 'username']
                                    for key in sensitive_keys:
                                        if key in resp_json:
                                            print(f"[+] Sensitive Data Exposure detected at {endpoint}: {key}")
                                            flag = True
                                    if len(resp_json_keys) >=10:
                                        print(f"[+] Potentialy Excessive Data Exposure Detected at {endpoint}")
                                        flag =True
                                except:
                                    continue
                        if 'html/text' in response.headers.get('Content-Type'):
                                try:
                                    sensitive_keys = ["password", "social security number", "credit card",'email','account', 'username']
                                    for key in sensitive_keys:
                                        if key in response.text.lower():
                                            print(f"[+] Potentialy Sensitive Data Exposure detected at {endpoint}: {key}")
                                            flag = True
                                except:
                                    continue
        if endpoint['method']=='POST':
            response = session.post(f"{endpoint['url']}", data=endpoint['body'], headers=endpoint['headers'])
            if response.status_code == 200:
                 if 'application/json' in response.headers.get('Content-Type'):
                        try:
                            resp_json = parse_json(response)
                            resp_json_data = json.loads(resp_json)
                            resp_json_keys = [i for i in resp_json_data.keys()]
                            sensitive_keys = ["password", "social security number", "credit card",'email','account', 'username']
                            for key in sensitive_keys:
                                if key in resp_json:
                                    print(f"[+] Sensitive Data Exposure detected at {endpoint['url']}: {key}")
                                    flag = True
                            if len(resp_json_keys) >=10:
                                print(f"[+] Potentialy Excessive Data Exposure Detected at {endpoint['url']}")
                                flag =True
                        except:
                            continue
    if flag==False:
        print("[-] No Excessive Data Exposure found")

def test_lack_of_resource_and_rate_limiting(): # Rate Limiting
        session = requests.Session()
        print(color("\n[*] Testing Lack of Resource and Rate Limiting", 'blue'))
        for endpoint in all_endpoints:
            if endpoint['method']=='GET':
                for _ in range(100):  # Arbitrary number to test rate limiting
                    response = session.get(f"{endpoint['url']}", headers=endpoint['headers'])
                    if response.status_code == 429:
                        print(color(f"[+] Rate Limiting detected with GET request at {endpoint}", 'green'))
                        break
                else:
                    print(f"[-] No Rate Limiting detected with GET Request to {endpoint}")
            if endpoint['method']=='POST':
                for _ in range(100):  # Arbitrary number to test rate limiting
                    response = session.post(f"{endpoint['url']}", data=endpoint['body'], headers=endpoint['headers'])
                    if response.status_code == 429:
                        print(color(f"[+] Rate Limiting detected with POST request at {endpoint}", 'green'))
                        break
                else:
                    print(f"[-] No Rate Limiting detected with POST request to {endpoint}")

def test_broken_function_level_authorization(): # Broken Function Level Authorization (BFLA)
        print(color("\n[*] Testing Broken Function Level Authorization (BFLA)\n", 'blue'))
        session = requests.Session()
        for endpoint in all_endpoints:
            if endpoint['method']=='POST':
                response = session.post(f"{endpoint['url']}", data=endpoint['body'], headers=endpoint['headers'])
                if 'application/json' in endpoint['headers']['Content-Type']:
                    req_json = parse_json(endpoint['body'])
                    req_json_data = json.loads(req_json)
                    req_json_keys = [i for i in req_json_data.keys()]
                    if response.status_code == 302 or response.status_code == 200:
                        response_1 = list(session.cookies.get_dict().items())
                        if "isAdmin" in req_json_keys or "Admin" in req_json_keys:
                            if "isAdmin" in req_json_keys:
                                if req_json_data["isAdmin"] == 0:
                                    req_json_data['isAdmin'] = 1
                                else:
                                    req_json_data['isAdmin'] = True
                                sent_data= json.dumps(req_json_data)
                            elif "Admin" in req_json_keys:
                                if req_json_data["Admin"] == 0:
                                    req_json_data['Admin'] = 1
                                else:
                                    req_json_data['Admin'] = True
                                sent_data= json.dumps(req_json_data)
                            resp_2 = session.post(f"{endpoint['url']}", json=sent_data, headers=endpoint['headers'])
                            if resp_2.status_code == 200:
                                response_2 = list(session.cookies.get_dict().items())
                                if response_1 != response_2:
                                    print(color(f"[+] Possible Function Level Authorization vulnerability detected at {endpoint['url']}", 'green'))
                            else:
                                print("[-] No BFLA Vuln Detected")
                        else:
                            print("[-] No BFLA Vuln Vector Detected")
                elif "application/x-www-form-urlencoded" in endpoint['headers']['Content-Type']:
                    data_keys = endpoint['body'].split('&')
                    data_keys_dict = dict(pair.split('=') for pair in data_keys)
                    data_keys = list(data_keys_dict.keys())
                    if response.status_code == 302 or response.status_code == 200:
                        response_1 = list(session.cookies.get_dict().items())
                        if "isAdmin" in data_keys or "Admin" in data_keys:
                            if "isAdmin" in data_keys:
                                if data_keys_dict["isAdmin"] == 0:
                                    data_keys_dict['isAdmin'] = 1
                                else:
                                    data_keys_dict['isAdmin'] = True
                                sent_data= '&'.join([f'{key}={value}' for key, value in data_keys_dict.items()])
                            elif "Admin" in data_keys:
                                if data_keys_dict["Admin"] == 0:
                                    data_keys_dict['Admin'] = 1
                                else:
                                    data_keys_dict['Admin'] = True
                                sent_data= '&'.join([f'{key}={value}' for key, value in data_keys_dict.items()])
                            resp_2 = session.post(f"{endpoint['url']}", data=sent_data, headers=endpoint['headers'])
                            if resp_2.status_code == 200:
                                response_2 = list(session.cookies.get_dict().items())
                                if response_1 != response_2:
                                    print(color(f"[+] Possible Function Level Authorization vulnerability detected at {endpoint['url']}", 'green'))
                            else:
                                print("[-] No BFLA Vuln Detected")
                        else:
                            print("[-] No BFLA Vuln Vector Detected")

def replace_query_parameter(url, param_to_replace, new_value):   # Helper Function for SSRF
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    if param_to_replace in query_params:
        query_params[param_to_replace] = [new_value]
    new_query_string = urllib.parse.urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query_string)
    return urllib.parse.urlunparse(new_url)

def has_url_in_json_body(data):   # Helper Function for SSRF
    def contains_url(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if contains_url(value):
                    return True, key
        elif isinstance(obj, list):
            for item in obj:
                if contains_url(item):
                    return True
        elif isinstance(obj, str):
            parsed_value = urlparse(obj)
            if parsed_value.scheme and parsed_value.netloc:
                return True
        return False

    return contains_url(data)

def has_url_in_form_body(data):   # Helper Function for SSRF
    def contains_url(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if contains_url(value):
                    return True, key
        elif isinstance(obj, list):
            for item in obj:
                if contains_url(item):
                    return True
        elif isinstance(obj, str):
            parsed_value = urlparse(obj)
            if parsed_value.scheme and parsed_value.netloc:
                return True
            elif parsed_value.path:
                return True
        return False

    return contains_url(data)

def test_ssrf():
    print(color("\n[*] Testing Server Side Request Forgery", 'blue'))
    session = requests.Session()
    flag = False
    for endpoint in all_endpoints:
        if endpoint['method']=='GET':
            if has_url_query_parameter(endpoint['url']):
                _, param_url = has_url_query_parameter(endpoint['url'])
                new_url = replace_query_parameter(endpoint['url'], param_url, '127.0.0.1')
                response = session.get(new_url, headers=endpoint['headers'], allow_redirects=False)
                if response.status_code ==500:
                    print(color(f"[+] Potential SSRF vulnerability found: {new_url}", 'green'))
                    flag = True
                elif response.status_code == 200:
                    if "server error" in response.text:
                        pass
                    else:
                        print(color(f"[+] Potential SSRF vulnerability found: {new_url}", 'green'))
                        flag = True
        elif endpoint['method']=='POST':
            if 'application/json' in endpoint['headers']['Content-Type']:
                req_json = parse_json(endpoint['body'])
                req_json_data = json.loads(req_json)
                if has_url_in_json_body(req_json_data):
                    _, param = has_url_in_json_body(req_json_data)
                    req_json_data[param] = '127.0.0.1'
                    response = session.post(endpoint['url'], json=req_json_data, headers=endpoint['headers'], allow_redirects=False)
                    if response.status_code ==500:
                        print(color(f"[+] Potential SSRF vulnerability found: {endpoint['url']}", 'green'))
                        flag = True
                    elif response.status_code == 200:
                        if "server error" in response.text:
                            pass
                        else:
                            print(color(f"[+] Potential SSRF vulnerability found: {endpoint['url']}", 'green'))
                            flag = True
            elif "application/x-www-form-urlencoded" in endpoint['headers']['Content-Type']:
                data_keys = endpoint['body'].split('&')
                data_keys_dict = dict(pair.split('=') for pair in data_keys)
                if has_url_in_form_body(data_keys_dict):
                    _, param = has_url_in_form_body(data_keys_dict)
                    data_keys_dict[param] = "127.0.0.1"
                    updated_data = '&'.join([f'{key}={value}' for key, value in data_keys_dict.items()])
                    response = session.post(endpoint['url'], data=updated_data, headers=endpoint['headers'], allow_redirects=False)
                    if response.status_code ==500:
                        print(color(f"[+] Potential SSRF vulnerability found: {endpoint['url']}", 'green'))
                        flag = True
                    elif response.status_code == 200:
                        if "server error" in response.text:
                            pass
                        else:
                            print(color(f"[+] Potential SSRF vulnerability found: {endpoint['url']}", 'green'))
                            flag = True

def test_verbose_errors():
    print(color("\n[*] Testing Verbose Error Messages", 'blue'))
    verbose_error_keywords = ["exception", "traceback", "error", "stack trace"]
    flag = False

    for endpoint in all_endpoints:
        method = endpoint["method"]
        url = endpoint["url"]
        headers = endpoint['headers']
        body = endpoint['body']

        try:
            if method == "GET":
                response = requests.get(url, headers=headers, params=body)
            elif method == "POST":
                response = requests.post(url, headers=headers, data=body)
            else:
                continue

            if response.status_code >= 400:
                for keyword in verbose_error_keywords:
                    if keyword in response.text.lower():
                        print(color(f"[+] Potentially Verbose Error Messages Found at {url}", 'green'))
                        print(response.text)
                        flag = True
        except requests.exceptions.RequestException as e:
            print(f"Error sending request to {url}: {e}")
    if flag == False:
        print(f"[-] No Verbose Error Endpoints Found")

def test_default_credentials():
    print(color("\n[*] Testing Default Credentials", 'blue'))
    default_credentials = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "12345"),
        ("user", "user"),
        ("root", "root"),
        ("tomcat", "tomcat"),
        ("password", "password"),
        ("Admin","Admin"),
        ("admin","system"),
        ("root","pass"),
        ("user","password"),
        ("system","manager"),
        ("username","password"),
        ("webadmin","webibm"),
        ("root","rootpass"),
        ("admin", "passwd")
    ]
    flag = False

    for endpoint in all_endpoints:
        url = endpoint['url']
        headers = endpoint['headers']

        for username, password in default_credentials:
            try:
                if endpoint["method"] == "POST":
                    if 'application/json' in endpoint['headers']['Content-Type']:
                        req_json = parse_json(endpoint['body'])
                        req_json_data = json.loads(req_json)
                        req_json_keys = [i for i in req_json_data.keys()]
                        if 'username' in req_json_keys and 'password' in req_json_keys:
                            req_json_data['username']==username
                            req_json_data['password']==password
                            new_data = json.dumps(req_json_data)
                        elif 'uid' in req_json_keys and 'passw' in req_json_keys:
                            req_json_data['uid']==username
                            req_json_data['passw']==password
                            new_data = json.dumps(req_json_data)
                        elif 'user_id' in req_json_keys and 'password' in req_json_keys:
                            req_json_data['user_id']==username
                            req_json_data['password']==password
                            new_data = json.dumps(req_json_data)
                        else:
                            req_json_data[req_json_keys[0]]==username
                            req_json_data[req_json_keys[1]]==password
                        response = requests.post(url, headers=headers, json=new_data)

                    if 'application/x-www-form-urlencoded' in endpoint['headers']['Content-Type']:
                        req_data = str(endpoint['body'])
                        key_value_pairs = req_data.split('&')
                        key_value_dict = dict(pair.split('=') for pair in key_value_pairs)
                        keys = list(key_value_dict.keys())
                        if 'username' in keys and 'password' in keys:
                            modified_username = get_modified_data_param(req_data, 'username', username)
                            new_data = get_modified_data_param(modified_username, 'password', password)
                        elif 'uid' in keys and 'passw' in keys:
                            modified_username = get_modified_data_param(req_data, 'uid', username)
                            new_data = get_modified_data_param(modified_username, 'passw', password)
                        elif 'user_id' in keys and 'password' in keys:
                            modified_username = get_modified_data_param(req_data, 'user_id', username)
                            new_data = get_modified_data_param(modified_username, 'password', password)
                        else:
                            modified_username = get_modified_data(req_data, 1, username)
                            new_data = get_modified_data(modified_username, 2, password)
                        response = requests.post(url, headers=headers, data=new_data, allow_redirects=False)
                    if response and response.status_code == 302:
                        if "Set-Cookie" in response.headers:
                            print(color(f"[+] Endpoint {url} has default credentials {username} and {password}", 'green'))
                            flag = True
            except requests.exceptions.RequestException as e:
                print(f"Error sending request to {url}: {e}")
    if flag==False:
        print("[-] No Endpoint with Default Credntials Found")


if __name__=="__main__":
    global all_endpoints
    banner()
    target_domain = str(input("Enter the target domain : "))
    print("""\nIn the next step
          
        1. Configure Broswer for Proxy using README.MD
                
        After the Proxy has started:--
                
        2. Browse the target website and explore every functionality on the target.
        3. When done press ESC(Escape) to stop proxy and start testing""")
    proceed = input(termcolor.colored(("\nPress ENTER key to start proxy continue logging traffic..."), 'green', attrs=['bold']))
    run_proxy(target_domain)
    all_endpoints = parse_request_logs()
    test_broken_object_level_authorization()
    test_broken_user_authentication()
    test_excessive_data_exposure()
    test_lack_of_resource_and_rate_limiting()
    test_broken_function_level_authorization()
    test_ssrf()
    test_verbose_errors()
    test_default_credentials()
