
import sys
import os
import argparse
from colorama import init, Fore, Style
from datetime import datetime
import re
import time
import asyncio
import subprocess
import json
import sqlite3
import ipaddress
import signal

from spnego import client

from hadi_logger import get_logger

# Centralized logger initialization
logger = get_logger(
    module_name=__name__,
    log_file=os.getenv("HADI_LOG_FILE", os.path.join("logs", "hadi-ir.log")),
    debug_mode=False  # Default to False, will be updated with command line args
)

from FAZapi import FAZapi
from helpers import *
from helpers import ConfigManager


# Define a signal handler
def signal_handler(sig, frame):
    print_to_console("\n")
    logger.warning("Canceled by user")
    sys.exit(0)

# Register the handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, signal_handler)

# Your existing code follows...

header_written = False
idx_asc = 0
DEBUG_MODE = False

is_redirected = None


init()

def print_banner():
    banner = f"""
{Fore.BLUE}
 ______   ___     ______      _                 _                
|  ____| / _ \   |___  /     | |               | |               
| |__   / /_\ \     / /      | |     ___   ___ | | ___   _ _ __  
|  __|  |  _  |    / /       | |    / _ \ / _ \| |/ / | | | '_ \ 
| |     | | | |   / /__      | |___| (_) | (_) |   <| |_| | |_) |
|_|     \_| |_/  /_____|     |______\___/ \___/|_|\_\\__,_| .__/ 
                                                          | |    
                                                          |_|    
{Style.RESET_ALL}
Simple Fortinet FAZ Lookup Tool
(C) Ibrahim Hakami - 1b0x1R
July 2024
Version 0.1
DISCLAIMER - USE AT YOUR OWN RISK
"""

    # Ensure encoding is set to utf-8
    sys.stdout.reconfigure(encoding='utf-8')
    print_to_console(banner)
 


def get_timeline(db_path, logtype):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        query = f'''
        SELECT hour_start
        FROM {logtype}_timeline
        ORDER BY hour_start
        '''

        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()

        timeline = [datetime.strptime(row[0], '%Y-%m-%d %H:%M') for row in results]
        return timeline

    except sqlite3.Error as e:
        logger.warning(f"An error occurred: {e}")
        return None
        

def check_time_range(timeline, start_time, end_time):
    # Convert start_time and end_time to datetime objects if they're strings
    if isinstance(start_time, str):
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M')
    if isinstance(end_time, str):
        end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M')

    # Check if timeline is not empty
    if not timeline:
        return False

    # Get the minimum and maximum times from the timeline
    min_time = min(timeline)
    max_time = max(timeline)

    # Check if both start_time and end_time are within the timeline range
    return min_time <= start_time <= max_time and min_time <= end_time <= max_time


def execute_survey_fields():
    tids = [tid for tid in [FAZapi.search_request(args.logtype, '', args.st, args.et) for _ in range(10)] if tid is not None and tid != -11]
    total_queries = 1  # or however many queries you expect to process
    surveyed_fields = survey_fields(tids, total_queries)
    return surveyed_fields


def validate_ip(ip_string):
    # Check if there's more than one '*' in the IP string
    if ip_string.count('*') > 1:
        return False
        
    ip_string = ip_string.strip('"')    
    # Case 1: Full IP address with CIDR notation
    if '/' in ip_string:
        
        try:
            ip_string = ip_string.strip('"')
            ipaddress.ip_network(ip_string, strict=False)
            return True
        except ValueError:
            return False
    
    # Case 2: Full IP address without CIDR notation
    if '*' not in ip_string:
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    # Case 3: IP address with wildcards
    parts = ip_string.split('.')
    if len(parts) > 4:
        return False
    
    for part in parts:
        if part == '*':
            continue
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    
    return True


def validate_port(port_string):
    try:
        port = int(port_string)
        return 0 <= port <= 65535
    except ValueError:
        return False

def validate_query(query, fields):
    # Remove logical operators for individual key-value pair validation
    modified_query = re.sub(r'(\s+or\s+|\s+and\s+)', ' ', query)
    
    # Split the query into key-value pairs
    pairs = re.findall(r'(\w+)[=~><](\S+)', modified_query)
    
    logger.debug(f"Parsed query pairs: {pairs}")
    
    # If there are no pairs, check if the query is not empty
    if not pairs:
        logger.debug(f"No key-value pairs found. Query is {pairs}")
        return False
    
    for key, value in pairs:
        logger.debug(f"Validating pair: {key}={value}")
        # Strip any extraneous characters
        value = value.replace(')', '').replace('(','')
        if key not in fields:
            print_to_console(f"Invalid field: {key}. \nAllowed fields are: {', '.join(fields)}")
            return False
            
        if key.lower() in ['src', 'dst', 'srcip', 'dstip', 'transip']:
            if not validate_ip(value):
                logger.error(f"Invalid IP address: {value}")
                return False
        elif 'port' in key.lower():
            if not validate_port(value):
                logger.error(f"Invalid port: {value}")
                return False
        else:
            logger.debug(f"Key '{key}' does not require special validation.")
    
    logger.debug("Query validation successful.")
    return True




def is_process_running(devtype):
    LOCK_FILE = f"{devtype}.lock"
    return os.path.exists(LOCK_FILE)


def update_SQLiteDB(args, devtype):
    if is_process_running(devtype):
        print_to_console("An update_SQLiteDB process is already running. Please wait for it to finish.")
    else:
        python_executable = sys.executable
        subprocess_script_path = os.path.abspath("FAZsqlite.py")
        args_json = json.dumps(vars(args))
        cmd = [python_executable, subprocess_script_path, args_json]

        with open(os.path.join('FAZlogs', 'update.log'), 'w') as log_file:
            # Check platform and use appropriate flags
            if sys.platform.startswith('win'):
                # Windows-specific code
                process = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=log_file,
                    creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                # Unix-like systems (Linux, macOS)
                process = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=log_file,
                    start_new_session=True  # This is the Unix equivalent
                )

            log_file.write(f"Started a background process to SQLite DB with pid: {str(process.pid)}\n")


def setup_argument_parser():
    parser = argparse.ArgumentParser(description='Log search script for FortiAnalyzer')
    parser.add_argument("host", help="FortiAnalyzer IP/domain")
    parser.add_argument('adom', choices=['waf', 'proxy', 'firewall'], help='ADOM type')
    parser.add_argument('-query', default='', help='Search query (optional)')
    parser.add_argument('-st', '--starttime', required=True, help='Start time in "YYYY-MM-DD HH:MM" format')
    parser.add_argument('-et', '--endtime', required=True, help='End time in "YYYY-MM-DD HH:MM" format')
    parser.add_argument('-r', default='table', choices=['table', 'csv', 'json'], help='Output format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-logtype', default='traffic', choices=['traffic', 'app-ctrl', 'attack', 'content', 'event', 'history', 'virus', 'webfilter'], help='Log type')
    parser.add_argument('-sl', '--suspect-list', type=str, help='Path to the suspicious srcip list JSON file')
    parser.add_argument('-timeout', type=int, default=60, help='Timeout for fetching data for a TID (in seconds)')
    parser.add_argument('-fields', action='store_true', help='List fields available for the provided logtype')
    parser.add_argument('-update-wl', action='store_true', help='Update white list URLS file')
    parser.add_argument('-update-db', action='store_true', help='Update SQLite DB')

    return parser


def main():

    parser = setup_argument_parser()
    args = parser.parse_args()

    print_banner()


    logger.debug_mode = args.verbose
    logger.info("Logger is setup correctly")

    # Log dbg stuff
    command = "python " + " ".join(sys.argv)
    logger.log("NOTICE", "Command executed: %s" % command)
    logger.log("DEBUG", "Options: %s" % args)

    os.makedirs('FAZlogs', exist_ok=True)

    # try:

    config = ConfigManager()
    if not config.load_config(args):
        return
    FORTI = 'https://' + args.host + '/jsonrpc'

    logger.debug(f"Successfully extracted information for ADOM type: {args.adom}")
    logger.debug(f"FortiFaz: {FORTI}")
    logger.debug(f"ADOM_NAME: {config.adom}")
    logger.debug(f"Device ID: {config.devid}")
    logger.debug(f"Device type: {config.devtype}")
    logger.debug(f"Log Type: {args.logtype}")
    logger.debug(f"Fields: {config.fields}")


    # The instance client must be created here to refresh the session_cookie that can be used for update_db.
    # If the session_cookie expired and update_db want to refresh, we will not be able, because it is in the background
    # and detache. In addition, instructions like "Enter your username:" and "Enter Password: " will go into the log file.
    # Any way, you must fix this issue, todirect user input to console even if detached

    client = FAZapi(args, config)

    if args.update_db:
        if args.query:
            args.query = args.query.replace('\'', '"')
            if 'LIKE' in args.query:
                args.query = args.query.replace(' ', '').replace('LIKE', '~').replace('%', '')
            
            logger.debug(f"Validating query: {args.query}")
            if not validate_query(args.query, config.fields):
                logger.error(f"Query is invalid: {args.query}")
                return
            logger.debug("Query validation successful.")  
        else:
            args.query = ''
            
        update_SQLiteDB(args, config.devtype)
        # FAZsqlite.execute_regular_search()
        logger.info("Updating SQLite DB in the background...")
        return

    db_path = os.path.join('FAZlogs', f'{config.devtype}.db')

    # Query the timeline table
    timeline = get_timeline(db_path, args.logtype)
    
    # print_to_console(timeline)
    # if timeline:
        # for itime in timeline:
            # print_to_console(itime)
    # else:
        # print_to_console("Failed to retrieve timeline.")
        
     # Check the time range
    time_range_valid = False
    time_range_valid = check_time_range(timeline, args.starttime, args.endtime)

    data_dict = None
    if 'TOP' in args.query:
        time_range_valid = True
    
    if time_range_valid:
        logger.info("Running query on SQLite DB..")
        try:
            if os.path.exists(db_path):
                with FAZsqlite.get_db_connection(db_path) as conn:
                    start_time = time.time()
                    data_dict = FAZsqlite.SQLiteRead(conn, config.devtype, args.logtype, args.query, args.st, args.et)
                    end_time = time.time()
                    logger.info(f"Time taken to execute query: {end_time - start_time} seconds")

                if data_dict:
                    if 'TOP' in args.query:
                        for http_url, count in data_dict:
                            logger.info(f"{http_url}\t{count}")
                    else:
                        logger.info(f"Successfully read FAZlogs\{config.devtype}.db {args.logtype} logs.")
                        results_resp_json = {"result": {"data": data_dict}}
                        logger.info(f"Start printing results of query to {config.devtype} {args.logtype}: {args.query}")
                        print_logs(results_resp_json, config.fields, 0, 1)
            else:
                logger.warning(f"The SQLite DB FAZlogs\{config.devtype}.db not found!")
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                logger.warning("SQLite DB locked!")

    if not data_dict or not time_range_valid:
        logger.info("No results returned from SQLite DB!")
        if 'TOP' in args.query:
            return
        logger.info("Running query on FAZ ...")
        
        local_traffic = """!((dstip='172.16.0.0/12' and srcip='10.0.0.0/8') or (srcip='172.16.0.0/12' and dstip='10.0.0.0/8') or 
        (srcip='10.0.0.0/8' and dstip='10.0.0.0/8') or (srcip='172.16.0.0/12' and dstip='172.16.0.0/12'))"""
        
        if args.query:
            args.query = args.query.replace('\'', '"')
            if 'LIKE' in args.query:
                args.query = args.query.replace(' ', '').replace('LIKE', '~').replace('%', '')
            
            logger.debug(f"Validating query: {args.query}")
            if not validate_query(args.query, config.fields):
                logger.error(f"Query is invalid: {args.query}")
                return
            logger.debug("Query validation successful.")  
            
        else:
            args.query = local_traffic

        start_execution_time = time.time()
        result_printer = ResultsPrinter()
        print_logs = result_printer.print_logs

        whitelist_ips: List[str] = []
        # Initialize the log printer
        log_printer = ResultsPrinter()

        # Create a callback function that uses the log_printer
        def callback(results_resp_json):
            log_printer.print_logs(
                results_resp_json,
                config.fields,
                args.r,
                whitelist_ips,
                args.adom
            )

        total = client.search(callback)
        end_execution_time = time.time()
        execution_time = end_execution_time - start_execution_time
        logger.info(f"Total results: {total}")

        logger.info(f"Total execution time: {execution_time:.2f} seconds")
        sys.exit(0)
            
    logger.info("Finished your search query")

if __name__ == "__main__":
    main()
    