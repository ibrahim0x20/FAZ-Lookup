import os
import atexit
from tenacity import retry, stop_after_attempt, wait_exponential
import time
import asyncio
import aiohttp
import logging
import json
from color_logging import setup_colored_logging
import urllib

import FAZapi
import FAZsqlite

header_written = None
idx_asc = 0
DEBUG_MODE = False


class ProgressTracker:
    def __init__(self, total_queries):
        self.start_time = time.time()
        self.total_progress = 0.0
        self.last_logged_progress = 0.0
        self.last_logged_time = self.start_time
        self.total_queries = max(1, total_queries)  # Ensure total_queries is at least 1
        self.current_query = 0
        self.query_progresses = [0.0] * self.total_queries

    def update_progress(self, query_index, progress):
        self.query_progresses[query_index] = progress
        completed_queries = sum(1 for p in self.query_progresses if p >= 99.9)
        if self.total_queries > 0:
            self.total_progress = (sum(self.query_progresses)) / self.total_queries
        else:
            self.total_progress = 0.0

    def next_query(self):
        self.current_query += 1
        if self.current_query >= self.total_queries:
            self.total_progress = 100.0
            
progress_tracker = None

def initialize_progress_tracker(total_queries):
    global progress_tracker
    if total_queries <= 0:
        logging.warning("Total queries is zero or negative. Setting to 1 to avoid division by zero.")
        total_queries = 1
    if progress_tracker is None or progress_tracker.total_queries != total_queries:
        progress_tracker = ProgressTracker(total_queries)

@FAZapi.log_function_details(relevant_globals=["progress_tracker", "idx_asc"])
def update_and_log_progress(query_index, data):
    global progress_tracker, idx_asc

    if progress_tracker is None:
        return

    if not hasattr(progress_tracker, f'start_id_{query_index}'):
        setattr(progress_tracker, f'start_id_{query_index}', int(data[0]['id']))
        
    if not hasattr(progress_tracker, 'scale'):
    
        start_id = getattr(progress_tracker, f'start_id_{query_index}')
        progress_tracker.scale = int(start_id) - int(idx_asc)
        logging.info(f"Scale = {progress_tracker.scale}")

    # Calculate group progress
    if len(data) < 1000:
        group_progress = 100
    else:
        current_id = int(data[-1]['id'])
        start_id = getattr(progress_tracker, f'start_id_{query_index}')
        logging.debug(f"ProgressTracker = {progress_tracker.scale}")
        group_progress = min((start_id - current_id) / progress_tracker.scale * 100, 100)
        
    if group_progress > progress_tracker.query_progresses[query_index]:
        progress_tracker.update_progress(query_index, group_progress)
    
    logging.debug(f"Query Progresses: {progress_tracker.query_progresses}")

    formatted_progress = f"{progress_tracker.total_progress:.2f}%"
    formatted_group_progress = f"{group_progress:.2f}%"

    current_time = time.time()
    time_elapsed = current_time - progress_tracker.start_time

    # Calculate estimated time to finish
    if progress_tracker.total_progress > 0 and progress_tracker.total_progress < 100:
        rate_of_progress = progress_tracker.total_progress / time_elapsed
        time_remaining = (100 - progress_tracker.total_progress) / rate_of_progress
        expected_finish_time = time.strftime('%H:%M:%S', time.gmtime(time_remaining))
    elif progress_tracker.total_progress >= 100:
        expected_finish_time = '00:00:00'
    else:
        expected_finish_time = 'calculating...'

    if progress_tracker.total_progress <= 98.0:
        significant_change_threshold = 1.0
    elif progress_tracker.total_progress <= 99.0:
        significant_change_threshold = 0.01
    else:
        significant_change_threshold = 0.005
        
    if progress_tracker.total_progress > progress_tracker.last_logged_progress + significant_change_threshold:
        logging.info(f"Total Progress: {formatted_progress}, Estimated time to finish: {expected_finish_time}")
        progress_tracker.last_logged_progress = progress_tracker.total_progress
        progress_tracker.last_logged_time = current_time
        
    if group_progress >= 100.0 - 0.01 or group_progress > progress_tracker.last_logged_progress + significant_change_threshold:
        logging.debug(f"Progress query [{query_index}]: {formatted_group_progress}, Estimated time to finish: {expected_finish_time}")
        progress_tracker.last_logged_progress = group_progress
        progress_tracker.last_logged_time = current_time
        

WhiteListIPs = None
white_list_file = os.path.join('FAZlogs','WhiteListIPs.txt')
if os.path.exists(white_list_file):
    with open(white_list_file, 'r') as file:
        logging.debug(f"Reading white list IPs from 'WhiteListIPs.txt'")
        WhiteListIPs = [line.strip() for line in file.readlines()]
        
def print_logs(results_resp_json, fields, query_index, total_queries):
    global excluded_file_header_written, excluded_file, global_parsed_or_groups, header_written
    
    if args.r == 'json':
        print(json.dumps(results_resp_json, indent=4))
    else:
        data = results_resp_json["result"]["data"]
        # Print header to console if it hasn't been printed yet
        if not header_written:
            sep = ',' if args.r == 'csv' else ' '
            header = sep.join(fields)
            print(header)
            header_written = True
        sep = ',' if args.r == 'csv' else ' '
       
        if not data:
            # if total_queries > 1:
                # logging.info(f"No results due to the query with index: {query_index}")
            # else:
            logging.info(f"No data returned from the provided query: {args.query}")
            return
        batch = []
        try:
            for row_data in data:
                if args.adom == 'waf':
                    if 'http_url' in row_data and row_data['http_url'] is not None:
                        # Usage in your code
                        row_data['http_url'] = FAZsqlite.clean_url(row_data['http_url'])
                        
                    if 'http_agent' in row_data and row_data['http_agent'] is not None and row_data['http_agent'] == '':  
                        row_data['http_agent'] = FAZsqlite.clean_url(row_data['http_agent'])
                        
                else:
                    
                    dstip = row_data['dstip']
                    if dstip in WhiteListIPs:
                        logging.debug(f"Skipping line due to whitelist IP: {dstip}")
                        continue
                    if 'url' in row_data and row_data['url'] != '':
                        row_data['url'] = FAZsqlite.clean_url(row_data['url'])
                        
                    if 'msg' in row_data and row_data['msg'] != '':
                        row_data['msg'] = FAZsqlite.clean_url(row_data['msg'])
                        
                        
                formatted_row = [row_data.get(field, '') for field in fields]
                batch.append(sep.join(formatted_row))
                
                if len(batch) >= 100:
                    print('\n'.join(batch))
                    batch = []
                   
            print('\n'.join(batch))
            
        except IOError as e:
            logging.error(f"I/O error occurred: {e}")
        except Exception as e:
            logging.error(f"Unexpected error occurred: {e}")

        # Update and log progress
    update_and_log_progress(query_index, data)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
@FAZapi.log_function_details(relevant_globals=["progress_tracker", "header_written"])

async def fetch_search_results(tids, total_queries, result_processor):
    """
    Fetches the search results for the given task ID.
    
    Args:
        tid (str): The task ID of the search request.
        
    Returns:
        dict: The search results, or None if an error occurs.
    """

    # Reinitialize progress tracking attributes
    global progress_tracker
    # Reinitialize progress tracking attributes if needed
    initialize_progress_tracker(total_queries)
    
        
    total = 0
    

    queue = asyncio.Queue()
    processed_offsets = set()
    offset_lock = asyncio.Lock()
    active_tids = set(tids)

    async def fetch_results(session, tid, offset):
        results_resp_json = await FAZapi.search_request_status(session, tid, offset)
        return tid, offset, results_resp_json

    async def worker(session):

        nonlocal total
        global progress_tracker
        while active_tids:
            try:
                tid, offset = await queue.get()
                
                async with offset_lock:
                    if offset in processed_offsets:
                        queue.task_done()
                        if tid in active_tids:
                            queue.put_nowait((tid, offset + 1000))  # Try next offset
                        continue
                    processed_offsets.add(offset)
                
                tid, offset_value, results_resp_json = await fetch_results(session, tid, offset)
                if results_resp_json.get('result', {}).get('data', []):
                    logging.debug(f"Searc status succeeful for TID: {tid}")
                    try:
                        result_processor(results_resp_json)
                    except Exception as e:
                        logging.error(f"Error in result_processor for TID {tid}: {e}")
                    
                    return_lines = results_resp_json["result"]["return-lines"]
                    total += return_lines
                    
                    if return_lines == 1000:
                        new_offset = offset + return_lines
                        queue.put_nowait((tid, new_offset))
                    else:
                        active_tids.remove(tid)
                else:
                    if tid in active_tids:
                        active_tids.remove(tid)
                        if total == 0:
                            logging.debug(f"No logs found for TID {tid} with the specified criteria.")
                            FAZapi.print_to_console(f"Full Response Content from fetch_search_results: {json.dumps(results_resp_json, indent=4)}")
            except json.JSONDecodeError:
                logging.error(f"Error: Results response is not in JSON format for TID {tid}")
                logging.info(f"Full Response Content from fetch_search_results: {await results_resp_json.content}")
            except Exception as e:
                logging.error(f"Error occurred while fetching results for TID {tid}: {e}")

            logging.debug(f"Processed - TID: {tid}, Offset: {offset_value}")
            queue.task_done()

    async with aiohttp.ClientSession() as session:
        for tid in tids:
            queue.put_nowait((tid, 0))
        
        workers = [asyncio.create_task(worker(session)) for _ in range(min(10, len(tids)))]  # Number of concurrent workers

        await queue.join()  # Wait until all tasks are processed

        for w in workers:
            w.cancel()

    progress_tracker.next_query()

    return total


def init(params):
    global args, idx_asc
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
    FAZapi.fazapi(args)
    FAZapi.init_session()
    idx_asc = asyncio.run(FAZapi.start_idx())
    logging.info(f"Start logs index in the given time range: {idx_asc}")