# Example: python fortifaz-lookup19-progress-func.py -a waf -st "2024-06-20 20:00" -et "2024-06-21 00:00" -l attack -r csv > waf-attack.csv

import requests
import json
import os
import urllib3
import sys
import logging
import argparse
import urllib.parse
import re
import concurrent.futures
import time
import aiohttp
import asyncio
from asyncio_throttle import Throttler
from asyncio.exceptions import TimeoutError
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import List, Tuple, Dict, Optional
from aiohttp import ClientSession, ClientError
from asyncio import Semaphore
from datetime import datetime, timedelta
import fnmatch
import operator
import itertools
import functools
import inspect
from color_logging import setup_colored_logging
from concurrent.futures import ThreadPoolExecutor
import getpass
import ipaddress
from aiohttp import ClientTimeout
import socket


import base64
import gzip
import io
import csv



global excluded_file, excluded_file_header_written, log_files_data

# Global variables

user = None
password = None
FORTI = None
devid = None
ADOM_NAME = None
devtype = None
session_cookie = None

excluded_file = None
excluded_file_header_written = False
global_parsed_or_groups = None
args = None
is_redirected = None
log_files_data = None

DEBUG_MODE = False  # Set this based on your configuration
  
    
def sanitize_sensitive_values(args_dict):
    sanitized_dict = args_dict.copy()
    sensitive_keys = ['password', 'token', 'api_key', 'secret']  # Add more sensitive keys as needed
    for key in sensitive_keys:
        if key in sanitized_dict:
            sanitized_dict[key] = '***'
    return sanitized_dict
    
    
def safe_input(prompt):
    print_to_console(prompt)
    return input()


def print_to_console(message):
    if is_redirected:
        print(message, file=sys.stderr, flush=True)
        return
    print(message)

def is_debug_mode():
    return getattr(args, 'verbose', False)

def log_function_details(relevant_globals):
    def decorator_log_details(func):
        @functools.wraps(func)
        def wrapper_log_details(*args, **kwargs):
            if is_debug_mode():
                log_function_info(func, args, kwargs, relevant_globals)
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper_log_details(*args, **kwargs):
            if is_debug_mode():
                log_function_info(func, args, kwargs, relevant_globals)
            return await func(*args, **kwargs)

        def log_function_info(func, args, kwargs, relevant_globals):
            function_name = func.__name__
            
            # Get argument names
            arg_spec = inspect.getfullargspec(func)
            arg_names = arg_spec.args

            # Combine args and kwargs
            all_args = dict(zip(arg_names, args))
            all_args.update(kwargs)

            # Sanitize arguments
            sanitized_args = sanitize_sensitive_values(all_args)
            
            # Global variables used in this function
            global_vars = {var: globals().get(var) for var in relevant_globals if var in globals()}
            sanitized_globals = sanitize_sensitive_values(global_vars)
            
            logging.info(f"Function name: {function_name}")
            
            if sanitized_args:
                logging.info(f"Arguments and their values:")
                for arg, value in sanitized_args.items():
                    logging.info(f"  {arg}: {value}")
                    
            if sanitized_globals:
                logging.info(f"Global variables used in {function_name}:")
                for var, value in sanitized_globals.items():
                    logging.info(f"  {var}: {value}")

        if asyncio.iscoroutinefunction(func):
            return async_wrapper_log_details
        else:
            return wrapper_log_details

    return decorator_log_details
    



def read_json(file_path):
    """
    Reads and parses the JSON file at the given file path.
    
    Args:
        file_path (str): The path to the JSON file.
        
    Returns:
        dict: Parsed JSON data, or None if an error occurs.
    """
    if not os.path.exists(file_path):
        logging.error(f"The file '{file_path}' does not exist.")
        return None
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except json.JSONDecodeError:
        logging.error(f"The file '{file_path}' contains invalid JSON.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def extract_info(data):
    """
    Extracts information based on the device_type and log_type arguments.
    
    Args:
        data (dict): The JSON data.
        
    Returns:
        tuple: Extracted uri, devid, adom, devtype, and fields, or None if an error occurs.
    """
    
    device_type = args.adom
    log_type = args.logtype
    
    if device_type not in data:
        logging.error(f"The device type '{device_type}' is not valid. Valid options are: {', '.join(data.keys())}.")
        return None, None, None, None, None

    device_data = data[device_type]
    uri = data.get('uri')
    devid = device_data.get('devid')
    adom = device_data.get('adom')
    devtype = device_data.get('devtype')
    fields = device_data['logtype'].get(log_type)

    # Log the extracted information for debugging
    logging.debug(f"Extracted info for device type '{device_type}' and log type '{log_type}':")
    logging.debug(f"URI: {uri}")
    logging.debug(f"Device ID: {devid}")
    logging.debug(f"ADOM: {adom}")
    logging.debug(f"Device type: {devtype}")
    logging.debug(f"Fields: {fields}")

    return uri, devid, adom, devtype, fields

def call_FAZ_API(body):
    
    # Make the request to get the session cookie
    logging.debug(json.dumps(body, indent=4))
    
    try:
        session_resp = requests.post(FORTI, data=json.dumps(body), verify=False)
        session_resp.raise_for_status()  # Raise an exception for HTTP errors
        if session_resp.status_code != 200:
            logging.error(f"API returned status code {search_resp.status_code}")
            logging.error(f"call_FAZ_API: Response content: {search_resp.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error making request to FortiAnalyzer: {e}")
        return None
        
            # Rest of your code
    except Exception as e:
        logging.error(f"call_FAZ_API: {str(e)}")
        return None
        
    return session_resp
        
        
@log_function_details(relevant_globals=["FORTI", "user", "password"])
def get_session_cookie():
    """
    Authenticates with FortiAnalyzer and retrieves a session cookie.
    
    Returns:
        str: The session cookie, or None if an error occurs.
    """
    global user, password, FORTI, session_cookie, args
    # Authentication request body
    # Authenticate and get session cookie
    logging.debug("Attempting to get session cookie")

    file_path = 'session.key'

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            session_cookie = file.readline().strip()
        
        validate = check_session(args.st, args.et)
        
        if validate and validate != -11:
            close_tid(validate)
            return session_cookie


    user = safe_input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    # session_cookie = get_session_cookie()
    
     # Save the new session cookie
    
    body1 = {
        "method": "exec",
        "params": [
            {"url": "/sys/login/user", "data": {"passwd": password, "user": user}}
        ],
        "id": 1,
        "jsonrpc": "2.0"
    }
    # Make the request to get the session cookie
    
    session_resp = call_FAZ_API(body1)
    # Check if the response is valid JSON and contains the session key
    
    if session_resp:
        try:
            session_resp_json = session_resp.json()
            if 'session' in session_resp_json:
                session_cookie = session_resp_json["session"]
                with open('session.key', 'w') as file:
                    file.write(session_cookie)
                logging.debug("Successfully obtained session cookie")
                logging.info("Successfully logged in")
                return session_cookie
            else:
                logging.error("'session' key not found in the response")
                logging.info(f"Full Response from get_session_cookie: {session_resp_json}")
                return None
        except json.JSONDecodeError:
            logging.error("Error: Session response is not in JSON format")
            logging.info(f"Full Response Content from get_session_cookie: {session_resp.content}")
            return None

def is_server_online(host, port, timeout=5):
    """Check if the server is online."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error as ex:
        logging.error(f"Server {host}:{port} is not accessible: {ex}")
        return False            
        
def check_session(startTime, endTime, time_order = 'desc'):
    """
    Starts a log search request with the given query and time range.
    
    Args:
        query (str): The search query.
        startTime (str): The start time in 'YYYY-MM-DD HH:MM' format.
        endTime (str): The end time in 'YYYY-MM-DD HH:MM' format.
        
    Returns:
        str: The task ID (tid) of the search request, or None if an error occurs.
    """
    
    global ADOM_NAME, devid, session_cookie

    body2 = {
        "id": 2,
        "jsonrpc": "2.0",
        "method": "add",
        "params": [
            {
                "apiver": 3,
                "filter": "",
                "logtype": "traffic",
                "device": [{"devid": devid}],
                "time-order": time_order,
                "time-range": {"start": startTime, "end": endTime},
                "url": f"/logview/adom/{ADOM_NAME}/logsearch",
            }
        ],
        "session": session_cookie,
    }

    # Make the request to start the log search
    host = FORTI.split('://')[1].split('/')[0]
    if  not is_server_online(host, 443):
        logging.error(f"FORTI FAZ: {host} is not online. Aborting.")
        sys.exit(1)
        
    session_resp = call_FAZ_API(body2)
    
    if session_resp:
        try:
            search_resp_json = session_resp.json()
            
            if 'result' in search_resp_json:
                if isinstance(search_resp_json['result'], list) and len(search_resp_json['result']) > 0:
                    if 'status' in search_resp_json['result'][0] and 'code' in search_resp_json['result'][0]['status']:
                        if search_resp_json["result"][0]["status"]["code"] == -11:
                            logging.info(f"You are logged out. Please login again!")
                            if args.verbose:
                                logging.info(f"Session cookie expired: {search_resp_json['result'][0]['status']['message']}")
                            tid = search_resp_json["result"][0]["status"]["code"]
                        else:
                            tid = search_resp_json["result"].get("tid")
                    else:
                        tid = search_resp_json["result"].get("tid")
                elif isinstance(search_resp_json['result'], dict):
                    tid = search_resp_json["result"].get("tid")
                else:
                    logging.error(f"Unexpected 'result' structure: {search_resp_json['result']}")
                    tid = None
            elif 'error' in search_resp_json:
                message = search_resp_json["error"].get('message', 'Unknown error')
                # logging.error(f"Invalid command line data: {message}")
                logging.error(f"Invalid command line data: {session_resp.content}")
                tid = None
            else:
                logging.error(f"Unexpected response structure: {search_resp_json}")
                tid = None

        except json.JSONDecodeError:
            logging.error("Request response is not in JSON format")
            logging.info(f"Full Response Content from check_session: {search_resp.content}")
            tid = None
        
        return tid
    
        
def logout():
    global FORTI, session_cookie
    request = {
        "method": "exec",
        "params": [
            {
                "url": "/sys/logout"
            }
        ],
        "session": session_cookie,
        "id": 5
    }

    try:
        response = requests.post(FORTI, json=request, verify=False)
        
        if response.status_code != 200:
            logging.error(f"API returned status code {response.status_code}")
            logging.error(f"Response content: {response.text}")
            return 

    except Exception as e:
        logging.error(f"Error in logout request: {str(e)}")
        return 
        
    try:
        resp_json = response.json()
        if 'result' in resp_json and isinstance(resp_json['result'], list) and len(resp_json['result']) > 0:
            if 'status' in resp_json['result'][0] and 'message' in resp_json['result'][0]['status']:
                message = resp_json['result'][0]['status']['message']
                if args.verbose:
                    logging.info(f"Logout successful: {message}")
            else:
                logging.error("'status' or 'message' not found in the logout response")
                logging.info(f"Full Response from check_session: {resp_json}")
        else:
            logging.error("'result' not found or not in expected format in the logout response")
            logging.info(f"Full Response from check_session: {resp_json}")
    except json.JSONDecodeError:
        logging.error("Logout response is not in JSON format")
        logging.info(f"Full Response Content from check_session: {response.content}")
    
    
# Function to check if file modification time is greater than 24 hours ago
def is_old_file(file_path):
    if not os.path.exists(file_path):
        return True  # File does not exist, so it's considered old
    else:
        # Get the modification time of the file
        mod_time = os.path.getmtime(file_path)
        # Calculate current time minus 24 hours
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        # Convert modification time to datetime object
        mod_time_dt = datetime.fromtimestamp(mod_time)
        # Compare modification time with 24 hours ago
        return mod_time_dt < twenty_four_hours_ago

@log_function_details(relevant_globals=["session_cookie", "devtype", "ADOM_NAME"])        
def list_logfiles():
    
    global  session_cookie, devtype
    
    FAZlogs = 'FAZlogs'
    file_name = f'{devtype}.json'
    file_path = os.path.join(FAZlogs, file_name)
    
    
    # Check if the file is old or does not exist
    if is_old_file(file_path):
        # Call list_logfiles(args.st, args.et) if file is old or does not exist
        session_cookie = get_session_cookie()
        if not session_cookie:
            sys.exit(1)
        logging.info("Updating log files list from FAZ server.")
    else:
        logging.info(f"Skipping list_logfiles since '{file_path}' is recent.")
        return
        
    devid = None
    if devtype == 'FortiWeb':
        devid = "FV-2KFTE22000040"
    elif devtype == '"Fortigate"':
        devid = 'FG181FTK22900868'
        
    body = {
        "id": 5,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "apiver": 3,
                "devid": devid,
                "url": f"/logview/adom/{ADOM_NAME}/logfiles/state",
                "vdom": "root"
            }
        ],
        # "time-range": {"start": startTime, "end": endTime},
        "session": session_cookie
    }
    
    files_list = call_FAZ_API(body)
    
    if files_list:
        files_list_json = files_list.json()
        with open(file_path, 'w') as file:
            file.write(json.dumps(files_list_json, indent=4))
        # print(files_list.content)
        


# Assuming you have already defined ADOM_NAME, FORTI, and session_cookie
def report_download_progress(filename, total_size, current_size):
    progress = (current_size / total_size) * 100  # Cap at 100%
    logging.info(f"Downloading {filename}: {progress:.2f}% complete")
    if current_size >= total_size:
        logging.info(f"Download of {filename} completed.")


def get_log_file(filename, fsize, device_id, vdom, max_bytes=None):
    global session_cookie
    offset = 0
    
    if max_bytes:
        chunk_size = max_bytes
    else:
        chunk_size = 52428800  # Maximum length
    
    total_size = int(fsize)  # Assuming 'fsize' is available from the file info
    all_content = b""
    
    
    while True:
        body = {
            "id": 5,
            "jsonrpc": "2.0",
            "method": "get",
            "params": [
                {
                    "url": f"/logview/adom/{ADOM_NAME}/logfiles/data",
                    "devid": device_id,
                    "vdom": vdom,
                    "filename": filename,
                    "data-type": "csv/gzip/base64",
                    "offset": offset,
                    "length": chunk_size,
                    "apiver": 3
                }
            ],
            "session": session_cookie
        }
        
        response = call_FAZ_API(body)
        
        if response is None:
            logging.error(f"Failed to retrieve content for {filename}")
            return None
        data = response.json()
        
        if 'result' not in data or not data['result']['data']:
            logging.warning(json.dumps(data, indent=4))
            return None
        content = data['result']['data']
        decoded_content = base64.b64decode(content)
        decompressed_content = gzip.decompress(decoded_content)
        
        all_content += decompressed_content
        
        if data['result']['length'] > chunk_size:
            offset +=  chunk_size
        else:
            offset = total_size
        # print(total_size, ': ', data['result']['length'])
        # Report progress
        report_download_progress(filename, total_size, offset)
        
        if offset >= total_size:
            break
    
    try:
        return all_content.decode('utf-8')
    except UnicodeDecodeError:
        logging.warning(f"UTF-8 decoding failed for {filename}, trying ISO-8859-1")
        return all_content.decode('iso-8859-1')

   
# @log_function_details(relevant_globals=["idx_asc", "header_written"])
class FieldSurveyor:
    def __init__(self):
        self.field_dic = {}

    def process(self, results_resp_json):
        data = results_resp_json["result"]["data"]
        for data_dict in data:
            for key, value in data_dict.items():
                if value is not None and value != 0 and value != "" and value != 'N/A' and value != 'undefined' \
                and 'Reserved' not in value and key != 'srcport' and key != 'src_port':
                    if key not in self.field_dic:
                        self.field_dic[key] = set()
                    self.field_dic[key].add(value)

    def get_survey_results(self):
        return [key for key, unique_values in self.field_dic.items() if len(unique_values) > 1]

def survey_fields(tids, total_queries):
    field_surveyor = FieldSurveyor()
    
    # Initialize progress tracker
    initialize_progress_tracker(total_queries)

    total = asyncio.run(fetchlogs.fetch_search_results(tids, total_queries, lambda results_resp_json: field_surveyor.process(results_resp_json)))

    logging.info(f"Total results processed: {total}")

    for tid in tids:
        FAZapi.FAZapi.close_tid(tid)

    return field_surveyor.get_survey_results()


@log_function_details(relevant_globals=["args.logtype",  "args.st", "args.et"])
async def list_fields():
    global args

    async with aiohttp.ClientSession() as session:
    
        validate = check_session(args.st, args.et)
        
        if validate and validate == -11:
            
            session_cookie = get_session_cookie()
            asyncio.run(list_fields())
            
        tid = FAZapi.search_request(args.logtype, '', args.st, args.et)

        if tid:
            try:
                results_resp_json = await FAZapi.search_request_status(session, tid, 0, 1)

                if results_resp_json.get('result', {}).get('data', []):
                    data = results_resp_json["result"]['data']
                    print_to_console(f"Available fields for VDOM {args.adom}: {json.dumps(results_resp_json, indent=4)}")

            except KeyError as e:
                if "error" in results_resp_json:
                    logging.error(f"{results_resp_json['error']['message']}")
                else:
                    logging.error(f"Unexpected response structure: {results_resp_json}")
                raise
            except Exception as e:
                logging.error(f"Error occurred during search_request_status: {str(e)}")
                raise
        
        FAZapi.FAZapi.close_tid(tid)
        
        
def logfields(logtype):

    body2 = {
        "id": 4,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "apiver": 3,
                "devtype": devtype,
                "logtype": logtype,
                "url": f"/logview/adom/{ADOM_NAME}/logfields"
            }
        ],
        "session": session_cookie,
    }

    
    fields = call_FAZ_API(body2)
    
    if fields:
        return fields.json()

        
@log_function_details(relevant_globals=['FORTI', "ADOM_NAME", "devid", "session_cookie"])
def search_request(logtype, query, startTime, endTime, time_order = 'desc'):
    global session_cookie
    """
    Starts a log search request with the given query and time range.
    
    Args:
        query (str): The search query.
        startTime (str): The start time in 'YYYY-MM-DD HH:MM' format.
        endTime (str): The end time in 'YYYY-MM-DD HH:MM' format.
        
    Returns:
        str: The task ID (tid) of the search request, or None if an error occurs.
    """
    
    global ADOM_NAME, devid, session_cookie

    body2 = {
        "id": 2,
        "jsonrpc": "2.0",
        "method": "add",
        "params": [
            {
                "apiver": 3,
                "filter": query,
                "logtype": logtype,
                "device": [{"devid": devid}],
                "time-order": time_order,
                "time-range": {"start": startTime, "end": endTime},
                "url": f"/logview/adom/{ADOM_NAME}/logsearch",
            }
        ],
        "session": session_cookie,
    }

    # Make the request to start the log search
    
    search_resp = call_FAZ_API(body2)
    
    try:
        search_resp_json = search_resp.json()
        # print(json.dumps(search_resp_json, indent=4))

        if 'result' in search_resp_json and 'tid' in search_resp_json['result']:
            tid = search_resp_json["result"]["tid"]
            # elif search_resp_json["result"][0]["status"]["code"] == -11:
                # logging.info(f"Session cookie expired: {search_resp_json['result'][0]['status']['message']}")
                # tid = -11
                
        elif 'error' in search_resp_json:
            # message = search_resp_json["error"][0]['message']
            message = search_resp_json["error"]['message']
            print(f"Invalid command line data: {message}")
            tid = None
            
        else:
            # logging.error("'tid' key not found in the search response")
            logging.error(f"Full Response from search_request: {search_resp_json}")
            tid = None
    except json.JSONDecodeError:
        logging.error("Search response is not in JSON format")
        logging.info(f"Full Response Content from search_request: {search_resp.content}")
        tid = None
    
    return tid


@log_function_details(relevant_globals=['FORTI', 'ADOM_NAME', 'session_cookie'])
def close_search_request(tid):
    body2 = {
        "id": 2,
        "jsonrpc": "2.0",
        "method": "delete",
        "params": [
            {
                "apiver": "3",
                "url": f"/logview/adom/{ADOM_NAME}/logsearch/{tid}"
            }
        ],
        "session": session_cookie,
    }
    
    try:
        close_resp = call_FAZ_API(body2)
        
        if close_resp is None:
            logging.error(f"Failed to get response from FAZ API for TID: {tid}")
            return None

        close_resp_json = close_resp.json()
        
        if 'result' in close_resp_json and 'status' in close_resp_json['result']:
            status = close_resp_json['result'].get('status', {})
            message = status.get('message')
            if message:
                return message
            else:
                logging.warning(f"No status message found in the response for TID: {tid}")
                return None
        elif 'error' in close_resp_json:
            error_message = close_resp_json['error'].get('message', 'Unknown error')
            error_code = close_resp_json['error'].get('code', 'Unknown code')
            logging.error(f"Server returned an error for TID {tid}. Code: {error_code}, Message: {error_message}")
            return f"Error: {error_message}"
        else:
            logging.error(f"Unexpected response structure for TID: {tid}")
            logging.info(f"Full Response from close_search_request: {close_resp_json}")
            return None

    except json.JSONDecodeError:
        logging.error(f"Closing search request {tid} response is not in JSON format")
        logging.info(f"Full Response Content from close_search_request: {close_resp.content}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error in close_search_request for TID {tid}: {str(e)}")
        return None


def close_tid(tid):
    if tid is None:
        logging.warning("Attempted to close None TID, skipping.")
        return

    try:
        status = close_search_request(tid)
        if status == "succeeded":
            if args.verbose:
                logging.info(f"Search request {tid} closed successfully.")
        elif status is None:
            logging.warning(f"Failed to close search request {tid}. No status returned.")
        elif status.startswith("Error:"):
            logging.warning(f"Failed to close search request {tid}. {status}")
        else:
            logging.warning(f"Unexpected status when closing search request {tid}. Status: {status}")
    except Exception as e:
        logging.error(f"Failed to close search request {tid}: {str(e)}")


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
@log_function_details(relevant_globals=["ADOM_NAME", "FORTI", "session_cookie", "args"])
async def search_request_status(session, tid, offset, limit=1000):
    global ADOM_NAME, FORTI, session_cookie, args
    progress = 0
    stuck_iterations = 0
    max_stuck_iterations = 50  # Reduced to detect stalling faster
    last_progress = -1
    start_time = asyncio.get_event_loop().time()
        
    timeout = float(args.timeout)  # default: 5 minutes timeout

    while progress < 100:
        current_time = asyncio.get_event_loop().time()
        if current_time - start_time > timeout:
            logging.warning(f"Timeout reached for TID {tid} and offset {offset}. Total time: {current_time - start_time:.2f}s")
            logging.info(f"Try again with timeout > the current timeout: (timeout={timeout}).")
            break

        body3 = {
            "id": 3,
            "jsonrpc": "2.0",
            "method": "get",
            "params": [
                {
                    "apiver": 3,
                    "limit": limit,
                    "offset": offset,
                    "url": f"/logview/adom/{ADOM_NAME}/logsearch/{tid}"
                }
            ],
            "session": session_cookie,
        }

        try:
            async with session.post(FORTI, json=body3, ssl=False, timeout=60) as response:
                try:
                    text = await response.text(encoding='utf-8')
                    results_resp_json = json.loads(text)
                except UnicodeDecodeError as e:
                    logging.warning(f"UnicodeDecodeError: {e}, trying iso-8859-1 encoding")
                    try:
                        text = await response.text(encoding='iso-8859-1')
                        results_resp_json = json.loads(text)
                    except Exception as e:
                        logging.error(f"Error decoding response: {e}")
                        raw_content = await response.read()
                        logging.info(f"Raw response content: {raw_content}")
                        raise
                except json.JSONDecodeError as e:
                    logging.error(f"JSONDecodeError: {e}")
                    logging.info(f"Full Response Content: {text}")
                    raise

                try:
                    progress = results_resp_json["result"]["percentage"]
                    
                    if progress == last_progress:
                        stuck_iterations += 1
                        logging.debug(f"Progress stuck at {progress}% for {stuck_iterations} iterations.")
                        if stuck_iterations >= max_stuck_iterations:
                            logging.debug(f"Progress stuck at {progress}% for TID {tid} and offset {offset}. Breaking out of loop.")
                            break
                    else:
                        stuck_iterations = 0
                        last_progress = progress
                    
                    logging.debug(f"Progress for TID {tid} and offset {offset}: {progress}%")
                    
                    if progress == 100:
                        logging.debug(f"Reached 100% progress for TID {tid} and offset {offset}.")
                        break
                        
                except KeyError as e:
                    if "error" in results_resp_json:
                        logging.error(f"Error in response: {results_resp_json['error']['message']}")
                        logging.info(f"Full Response Content: {json.dumps(results_resp_json, indent=4)}")
                    else:
                        logging.error(f"Unexpected response structure for TID {tid} and offset {offset}: {str(e)}")
                    raise

        except aiohttp.ClientResponseError as e:
            logging.error(f"HTTP error for TID {tid} and offset {offset}: {e.status}")
            raise
        except aiohttp.ClientError as e:
            logging.warning(f"Network error for TID {tid} and offset {offset}: {str(e)}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error in search_request_status: {str(e)}")
            raise

        await asyncio.sleep(2)  # Add a small delay between requests

    logging.debug(f"Exiting loop for TID {tid} and offset {offset}. Final progress: {progress}%")
    return results_resp_json
    

           
@log_function_details(relevant_globals=["args.logtype"])
async def start_idx():
    global args

    async with aiohttp.ClientSession() as session:
        idx_asc = 0

        tid2 = search_request(args.logtype, '', args.st, args.et, 'asc')
        
        if tid2:
            try:
                    
                results_resp_json = await search_request_status(session, tid2, 0, 1)

                if results_resp_json.get('result', {}).get('data', []):
                    idx_asc = results_resp_json["result"]['data'][0]['id']
                    
                close_tid(tid2)
        
                # total_logs = int(idx_desc) - int(idx_asc)
                
                logging.debug(f"Start logs index in the given time range: {idx_asc}") 
                # logging.debug(f"Last logs index in the given time range: {idx_desc}") 
                    
                    
            except KeyError as e:
                if "error" in results_resp_json:
                    logging.error(f"{results_resp_json['error']['message']}")
                else:
                    logging.error(f"Unexpected response structure: {results_resp_json}")
                idx_asc = None
                raise
            except Exception as e:
                logging.error(f"Error occurred during search_request_status: {str(e)}")
                idx_asc = None
                raise
        else:
            logging.error(f"Failed to calculate total logs.")
            
    return idx_asc


#****************************************************************************
#                       Execution
#****************************************************************************
def init_session():
    global session_cookie
    if not session_cookie:
        session_cookie = get_session_cookie()

def fazapi(params):

    global FORTI, devid, ADOM_NAME, devtype, is_redirected, args, session_cookie
    
    args = params
    
    # Set up logging with more informative format
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    setup_colored_logging(level=logging.INFO)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

        DEBUG_MODE = True  
        
    is_redirected = not sys.stdout.isatty()
    
    # Read configuration from JSON file
    file_path = 'FazLog-config.json'
    data = read_json(file_path)
    if not data:
        logging.error("Failed to read configuration file")
        return

    # Extract information from JSON
    logging.debug(f"Extracting information for ADOM type: {args.adom}")
    FORTI, devid, ADOM_NAME, devtype, fields = extract_info(data)


        
    if not all([FORTI, devid, ADOM_NAME, devtype]):
        logging.error("Failed to extract all required information from configuration")
        return    

        # logging.debug(f"Successfully extracted information for ADOM type: {args.adom}")
        # logging.info(f"FortiFaz: {FORTI}")
        # logging.info(f"ADOM_NAME: {ADOM_NAME}")
        # logging.info(f"Log Type: {args.logtype}")


    # Disable warnings for unverified HTTPS requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    session_cookie = get_session_cookie()
    
    return FORTI, devid, ADOM_NAME, devtype, fields 

            
