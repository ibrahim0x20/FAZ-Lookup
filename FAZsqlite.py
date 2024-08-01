import os
import sys
from datetime import datetime, timedelta
import json
import logging
from color_logging import setup_colored_logging
import FAZapi
import time
import sqlite3
import re
import random
import functools
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential
import aiohttp
import urllib
import fetchlogs


user = None
password = None
FORTI = None
devid = None
ADOM_NAME = None
devtype = None
fields = None
args = None
WhiteListURLs = None
WhiteListIPs = None

white_list_file = None

DEBUG_MODE = False

#Global variables
FAZlogs = 'FAZlogs'     # Directory that have all the required log files
log_files_data = None

is_redirected = not sys.stdout.isatty()



def is_private_ip(ip):
    private_ranges = [
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('192.168.0.0/16')
    ]
    
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in network for network in private_ranges)

def process_firewall_log(log_line):

    
    if is_private_ip(log_line['srcip']) and is_private_ip(log_line['dstip']):
        return None  # Exclude this line
    else:
        return log_line  # Keep this line



def print_to_console(message):
    if is_redirected:
        print(message, file=sys.stderr, flush=True)
        return
    print(message)



# def initialize_progress_tracker(total_queries):
    # global progress_tracker
    # if progress_tracker is None or progress_tracker.total_queries != total_queries:
        # progress_tracker = ProgressTracker(total_queries)
        

# progress_tracker = None


def top_http_url(conn, devtype, logtype):
    global WhiteListURLs, white_list_file
    cleaned = os.path.join('FAZlogs', 'CLEAN_LOCK')
    query = 'TOP 1000 http_url'
    
    delete_urls_from_db(conn, logtype, WhiteListURLs)
    # print(f"Running SQLiteRead with devtype={devtype} logtype={logtype}")
    results = SQLiteRead(conn, devtype, logtype, query) # White list URL based on the top used
    
    new_urls_count = 0
    new_urls = []
    if results:
        
        # print(f"Results obtained: {len(results)} entries")
        for url, count in results:
            if count >= 5000 and url not in WhiteListURLs:
                WhiteListURLs.append(url)
                new_urls.append(url)
                # print(f"{url}\t\t{count}")
                new_urls_count += 1
    
    if WhiteListURLs:
        with open(white_list_file, 'w') as file:
            file.write('\n'.join(WhiteListURLs))
        logging.info(f"White list updated with {new_urls_count} URLs")
        
        
        # if not os.path.exists(cleaned):
            # logging.info(f"First time cleaning SQLite DB from white listed URLs ...")
            # delete_urls_from_db(conn, logtype, WhiteListURLs)
            # with open(cleaned, 'w') as file:
                # file.write(f"{devtype}.db cleaned")
        
    if new_urls:
        logging.info(f"Start cleaning SQLite DB from white listed URLs ...")
        delete_urls_from_db(conn, logtype, new_urls)
        
    print("No new URLs to add to the white list")
    return None
    
def retry_on_locked_db(max_retries=5, base_delay=0.1):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e) and attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 0.1)
                        logging.warning(f"Database locked, retrying in {delay:.2f} seconds... (Attempt {attempt + 1}/{max_retries})")
                        time.sleep(delay)
                    else:
                        raise
            logging.error(f"Failed to execute operation after {max_retries} attempts")
            raise sqlite3.OperationalError("Database locked and max retries exceeded")
        return wrapper
    return decorator
    
       
@retry_on_locked_db()
def delete_urls_from_db(conn, logtype, wl_url):
    try:
        cursor = conn.cursor()
        sql = f"DELETE FROM {logtype} WHERE http_url = ?"
        
        # Convert wl_url to a list of single-item tuples if it's not already
        if not all(isinstance(item, tuple) for item in wl_url):
            wl_url = [(url,) for url in wl_url]
        
        cursor.executemany(sql, wl_url)
        conn.commit()
        print(f"Deleted {cursor.rowcount} URLs from the database.")
    except sqlite3.Error as e:
        logging.error(f"SQLite error while deleting URLs: {str(e)}")
        raise   

def get_db_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn
    

def delete_old_entries(devtype, logtype):
    # Calculate the threshold for one week ago
    one_week_ago = int(time.time()) - (7 * 24 * 60 * 60)
    
    # Database path
    db_path = os.path.join('FAZlogs', f'{devtype}.db')
    
    # SQL query to delete rows older than one week
    delete_query = f"""
    DELETE FROM {logtype} 
    WHERE itime < ?
    """
    
    # Connect to the SQLite database and execute the query
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        apply_optimizations(cursor)
        cursor.execute(delete_query, (one_week_ago,))
        conn.commit()
        print(f"Deleted rows older than one week from table {logtype} in database {devtype}.db.")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()

            
def convert_to_int(data):
    int_fields = ["itime", "http_request_bytes", "http_response_bytes", "http_retcode", "log_id", logidx]
    for field in int_fields:
        if field in data and isinstance(data[field], str) and data[field].isdigit():
            data[field] = int(data[field])
    return data


@FAZapi.log_function_details(relevant_globals=["devtype"])
def SQLiteWrite(results_resp_json, conn, logtype, fields):
    global devtype, WhiteListURLs, WhiteListIPs, args

    data = results_resp_json["result"]["data"]
    if not data:
        logging.info(f"No data returned from the provided query: {args.query}")
        return
    
    cursor = conn.cursor()
    
    # Apply optimizations before starting any transactions
    cursor.execute('PRAGMA journal_mode = WAL')
    cursor.execute('PRAGMA synchronous = NORMAL')
    cursor.execute('PRAGMA cache_size = 1000000')
    cursor.execute('PRAGMA locking_mode = EXCLUSIVE')
    cursor.execute('PRAGMA temp_store = MEMORY')
    
    # Specify which fields should be integers
    int_fields = ["itime", 'id', "http_request_bytes", "http_response_bytes", "http_retcode", "log_id", "threat_weight", "history_threat_weight"]
    
    # Create a table to store the data, using msg_id as the primary key
    create_table_sql = f'''
    CREATE TABLE IF NOT EXISTS {logtype} (
        {", ".join([f"{field} {'INTEGER' if field in int_fields else 'TEXT'}" for field in fields if field != 'id'])},
        id INTEGER PRIMARY KEY
    )
    '''
    cursor.execute(create_table_sql)
    
    # Compile exclusion patterns from exclude.txt
    exclude_patterns = []
    exclude_file = 'exclude.txt'
    
    if args.adom == 'waf':
        if os.path.exists(exclude_file):
            with open(exclude_file, 'r') as file:
                exclude_patterns = [re.compile(pattern.strip()) for pattern in file if pattern.strip()]
    
    
    # Prepare the INSERT statement
    columns = ', '.join(fields)
    placeholders = ', '.join(['?' for _ in fields])
    sql = f'INSERT OR REPLACE INTO {logtype} ({columns}) VALUES ({placeholders})'
    
    # Parse the data and insert into the database in batches
    batch_size = 50
    batch = []
    
    try:
        for line in data:
            if args.adom == 'waf':
                if 'http_url' in line and line['http_url'] is not None:
                    # Usage in your code
                    line['http_url'] = clean_url(line['http_url'])
                    
                # if 'http_agent' in line:
                    # if line['http_agent'] is not None and line['http_agent'] != "":
                        # value = line['http_agent']
                        # value = value.replace(',', ';').replace('%2C', ';').replace('\n', '').replace('$', '')
                        # value = value.replace('%0A', '{{0A}}').replace('%0D', '{{0D}}').replace('%2C', '{{2C}}').replace('%0a', '{{0a}}')
                        # value = urllib.parse.unquote(value)
                        # value = value.replace('{{0A}}', '%0A').replace('{{0D}}', '%0D').replace('{{2C}}', '%2C').replace('{{0a}}', '%0a')
                        # value = value.encode('cp850', errors='replace').decode('cp850')
                        # line['http_agent'] = str(value)

                    
                http_url = line['http_url']
                if http_url:
                    if any(pattern.match(http_url) for pattern in exclude_patterns):
                        logging.debug(f"Skipping line due to URL matches exclude regex : {http_url}")
                        continue
                    if http_url in WhiteListURLs:
                        logging.debug(f"Skipping line due to whitelist URL: {http_url}")
                        continue
                
                # batch.append([line[field] for field in fields]) ==> This has taken a lot of time because from me to solve it. 
                # If you try to extract value from a dictionary data while the key is not there, it will cause an error and breaks the program.
                # In my case, I'm getting the error on 'http_agent', but it deos not till me that it is missing in the row (line)
                # While the error is introduced and because I'm using 'async' and concurrent code to process data, and this is why we see the second error message.
                    # 2024-07-20 11:13:59,936 - ERROR - Error occurred while fetching results for TID 1229523399: 'http_agent'
                    # 2024-07-20 11:14:00,049 - ERROR - Error occurred while fetching results for TID 1481181379: Safety level may not be changed inside a transaction
                # selected_values = [row_data.get(field, '') for field in fields] 
                
                # The solution was to make sure the key is in the line before trying to extract values from it either by adding else statement to the above code such that 
                # else: line['http_agent'] = '' ==> This will add a new key to the line(row)
                # Or use the get() method as in the next statement. And this solution is the best as it will not solve only 'http_agent', 
                # but also any missing field in the data(line)
            else:
                dstip = line['dstip']
                if dstip in WhiteListIPs:
                        logging.debug(f"Skipping line due to whitelist IP: {dstip}")
                        continue
                
            batch.append([line.get(field, '') for field in fields])
            
            if len(batch) >= batch_size:
                cursor.executemany(sql, batch)
                batch = []

        # Insert any remaining data
        if batch:
            cursor.executemany(sql, batch)

        # Commit the changes
        conn.commit()
        
        fetchlogs.update_and_log_progress(0, data)

    except sqlite3.Error as e:
        conn.rollback()
        logging.error(f"SQLite error in SQLiteWrite: {str(e)}")
        raise
    finally:
        cursor.close()

    logging.debug(f"{len(data)} records has been successfully written to the SQLite database.")



def clean_url(url):
    if url is None:
        return None
    
    # Replace commas and newlines
    url = url.replace(',', ';').replace('\n', '')
    
    # Encode specific characters
    encode_map = {
        '%0A': '{{0A}}', '%0D': '{{0D}}', 
        '%2C': '{{2C}}', '%0a': '{{0a}}'
    }
    for key, value in encode_map.items():
        url = url.replace(key, value)
    
    # Decode the URL
    url = urllib.parse.unquote(url)
    
    # Decode specific characters back
    decode_map = {v: k for k, v in encode_map.items()}
    for key, value in decode_map.items():
        url = url.replace(key, value)
    
    # Handle encoding
    url = url.encode('cp850', errors='replace').decode('cp850')
    
    return url

@retry_on_locked_db()
def SQLiteRead(conn, devtype, logtype, condition, st=None, et=None):
    query = build_query(logtype, condition, starttime=st, endtime=et)
    if query is None:
        return None
    try:
        cursor = conn.cursor()
        apply_optimizations(cursor)
        cursor.execute(query)
        
        if 'DISTINCT' in condition or 'TOP' in condition:
            rows = cursor.fetchall()
            return rows
        else:
            column_names = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            return [dict(zip(column_names, row)) for row in rows]
    except sqlite3.Error as e:
        logging.error(f"SQLite error in query {query}: {str(e)}")
        return None
        


def add_single_quotes(text):
    def quote_match(match):
        full_match = match.group(0)
        param = match.group(1)
        operator = match.group(2)
        value = match.group(3)
        
        # Check if the value is already quoted
        if value.startswith("'") and value.endswith("'"):
            return full_match
        
        # Quote the value
        return f"{param}{operator}'{value}'"

    # Pattern to match http_url, http_host, and potentially other similar parameters
    pattern = r'((?:http_url|http_host|http_agent)\s*)((?:=|>|<|LIKE)\s*)([^\'"\s]+)'
    
    # Split the text by logical operators and parentheses, preserving the delimiters
    parts = re.split(r'(\s+AND\s+|\s+OR\s+|\s+NOT\s+|\(|\))', text)
    
    # Process each part
    for i, part in enumerate(parts):
        if re.search(pattern, part):
            parts[i] = re.sub(pattern, quote_match, part)
    
    # Join the parts back together
    return ''.join(parts)
    

def build_query(logtype, condition, starttime=None, endtime=None):
    # Convert start and end times to integer timestamps
    # if starttime:
        # start_itime = int(datetime.strptime(starttime, "%Y-%m-%d %H:%M").timestamp())
    # if endtime:
        # end_itime = int(datetime.strptime(endtime, "%Y-%m-%d %H:%M").timestamp())
    
    # Build the time condition
    time_condition = []
    if starttime:
        time_condition.append(f"itime > '{starttime}'")
    if endtime:
        time_condition.append(f"itime < '{endtime}'")
    time_condition = ' AND '.join(time_condition)

    if condition == '':
        base_query = f'SELECT * FROM {logtype}'
        where_clause = f'WHERE {time_condition}' if time_condition else ''
        print_to_console("Returning the first 100 results from SQLite")
        logging.debug(f"'{base_query} {where_clause} LIMIT 100'")
        return f'{base_query} {where_clause} LIMIT 100'

    elif 'DISTINCT' in condition:
        key, value = condition.split('=')
        base_query = f'SELECT DISTINCT {value} FROM {logtype}'
        where_clause = f'WHERE {time_condition}' if time_condition else ''
        return f'{base_query} {where_clause}'
    elif 'TOP' in condition:
        values = condition.split()
        base_query = f'SELECT {values[2]}, COUNT(*) as count FROM {logtype}'
        where_clause = f'WHERE {time_condition}' if time_condition else ''
        return f'{base_query} {where_clause} GROUP BY {values[2]} ORDER BY count DESC LIMIT {values[1]}'
    else:
        condition = condition.replace('!', 'NOT')
        condition = add_single_quotes(condition)
        logging.info(condition)
        where_conditions = [condition]
        if time_condition:
            where_conditions.append(time_condition)
        where_clause = 'WHERE ' + ' AND '.join(where_conditions)
        return f'SELECT * FROM {logtype} {where_clause}'
    

def apply_optimizations(cursor):
    optimizations = [
        'PRAGMA journal_mode = WAL',
        'PRAGMA synchronous = NORMAL',
        'PRAGMA cache_size = 1000000',
        'PRAGMA locking_mode = EXCLUSIVE',
        'PRAGMA temp_store = MEMORY'
    ]
    for opt in optimizations:
        cursor.execute(opt)

# def print_results(condition, rows):
    # if 'DISTINCT' in condition:
        # for value in rows:
            # print(value[0])
    # elif 'TOP' in condition:
        # for key, count in rows:
            # print(f"{key}\t{count}")



def update_time_tracking(devtype, logtype, new_oldest, new_newest):
    tracking_file = os.path.join("FAZlogs", "time_tracking.json")
    
    # Initialize the structure if the file doesn't exist
    if not os.path.exists(tracking_file):
        initial_structure = {
            "FortiWeb": {
                "logtype": {
                    "traffic": {"starttime": "", "endtime": ""},
                    "attack": {"starttime": "", "endtime": ""}
                }
            },
            "proxy": {
                "logtype": {
                    "traffic": {"starttime": "", "endtime": ""},
                    "event": {"starttime": "", "endtime": ""},
                    "webfilter": {"starttime": "", "endtime": ""},
                    "app-ctrl": {"starttime": "", "endtime": ""}
                }
            },
            "firewall": {
                "logtype": {
                    "traffic": {"starttime": "", "endtime": ""},
                    "attack": {"starttime": "", "endtime": ""},
                    "webfilter": {"starttime": "", "endtime": ""},
                    "app-ctrl": {"starttime": "", "endtime": ""}
                }
            }
        }
        with open(tracking_file, 'w') as file:
            json.dump(initial_structure, file, indent=4)

    # Read current values
    with open(tracking_file, 'r') as file:
        data = json.load(file)

    # Ensure the structure exists for the given devtype and logtype
    if devtype not in data:
        data[devtype] = {"logtype": {}}
    if logtype not in data[devtype]["logtype"]:
        data[devtype]["logtype"][logtype] = {"starttime": "", "endtime": ""}

    current_start = data[devtype]["logtype"][logtype]["starttime"]
    current_end = data[devtype]["logtype"][logtype]["endtime"]

    # Convert string times to datetime objects
    current_start = datetime.strptime(current_start, "%Y-%m-%d %H:%M:%S") if current_start else datetime.max
    current_end = datetime.strptime(current_end, "%Y-%m-%d %H:%M:%S") if current_end else datetime.min

    # Update values
    updated_start = min(current_start, new_oldest)
    updated_end = max(current_end, new_newest)

    # Store updated values
    data[devtype]["logtype"][logtype]["starttime"] = updated_start.strftime("%Y-%m-%d %H:%M:%S")
    data[devtype]["logtype"][logtype]["endtime"] = updated_end.strftime("%Y-%m-%d %H:%M:%S")

    # Write updated values
    with open(tracking_file, 'w') as file:
        json.dump(data, file, indent=4)

# Example usage:
# update_time_tracking("FortiWeb", "traffic", datetime(2023, 1, 1), datetime(2023, 1, 2))
# update_time_tracking("proxy", "webfilter", datetime(2023, 1, 3), datetime(2023, 1, 4))



def check_idx(conn, devtype, logtype, idx):
    query = f'SELECT {logidx} FROM {logtype} WHERE {logidx} = ?'
    

    try:
            cursor = conn.cursor()
            # apply_optimizations(cursor)
            cursor.execute(query, (idx,))
            rows = cursor.fetchall()
            return rows

    except sqlite3.Error as e:
        logging.error(f"SQLite error in query {query}: {str(e)}")
        return None


def create_lock():
    global devtype
    LOCK_FILE = f"{devtype}.lock"
    with open(LOCK_FILE, 'w') as f:
        f.write(str(os.getpid()))

@FAZapi.log_function_details(relevant_globals=["args", "fields", "devtype"])        
def execute_regular_search():
    global devtype, args, fields
    logtype = args.logtype
    
    db_path = os.path.join('FAZlogs', f'{devtype}.db')
    
    conn = get_db_connection(db_path)

    # cursor = conn.cursor()
    # # Execute the DROP TABLE statement
    # cursor.execute(f"DROP TABLE IF EXISTS {args.logtype}")
    # print("Dropped table:", args.logtype)
    # conn.commit()
    # return
        
    create_lock()
        
    tids = [tid for tid in [FAZapi.search_request(args.logtype, args.query, args.st, args.et) for _ in range(10)] if tid is not None and tid != -11]
    total = asyncio.run(fetchlogs.fetch_search_results(tids, 1, lambda results_resp_json: SQLiteWrite(results_resp_json, conn, logtype, fields)))
    # tids, lambda results_resp_json: default_result_processor(results_resp_json, fields, 0, 1)
    
    # for tid in tids:
        # FAZapi.close_tid(tid)

    logging.info(f"Total results: {total}")
    

def table_exists(conn, table_name):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None
    
 


def update_time_range(log_file, oldest_time, newest_time):
    start_time = datetime.strptime(log_file['starttime'], "%Y-%m-%d %H:%M:%S")
    end_time = datetime.strptime(log_file['endtime'], "%Y-%m-%d %H:%M:%S")
    return min(oldest_time, start_time), max(newest_time, end_time)

                

#******************************************************************************************
#                                   Execution
#******************************************************************************************
# 1. Add filtering most common and safe URLs
# 2. Logs aging ==> Remove from SQLit db after 7 days
# 3. When  downloading logs from FortiAnalyzer, detattach the downlaoding execution from the main program: FAZ-Lookup.py

def FAZsqlite(params):
    global args, devtype, fields, logidx, srcip, dstip, policy, host, log_id, WhiteListURLs, WhiteListIPs, white_list_file, DEBUG_MODE
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


    try:
        results  = FAZapi.fazapi(args)
        FORTI, devid, ADOM_NAME, devtype, fields = results
        
        # Your existing code here
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return
        
    
    # srcip = 'src' if args.adom == 'waf' else 'srcip'
    # dstip = 'dst' if args.adom == 'waf' else 'dstip'
    # policy = 'policy' if args.adom == 'waf' else 'policyid'
    # host = 'http_host' if args.adom == 'waf' else 'hostname'
    # log_id = 'log_id' if args.adom == 'waf' else 'logid'
    
    if args.adom == 'waf':
        white_list_file = os.path.join('FAZlogs','WhiteListURL.txt')
        if os.path.exists(white_list_file):
            with open(white_list_file, 'r') as file:
                logging.debug(f"Reading white list URLs from 'WhiteListURL.txt'")
                WhiteListURLs = [line.strip() for line in file.readlines()]
    else:
        
        white_list_file = os.path.join('FAZlogs','WhiteListIPs.txt')
        if os.path.exists(white_list_file):
            with open(white_list_file, 'r') as file:
                logging.debug(f"Reading white list IPs from 'WhiteListIPs.txt'")
                WhiteListIPs = [line.strip() for line in file.readlines()]
    
        