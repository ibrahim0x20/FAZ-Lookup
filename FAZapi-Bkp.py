# Example: python fortifaz-lookup19-progress-func.py -a waf -st "2024-06-20 20:00" -et "2024-06-21 00:00" -l attack -r csv > waf-attack.csv

import requests
import aiohttp
from datetime import datetime, timedelta
from tenacity import retry, stop_after_attempt, wait_exponential
import getpass
import base64
import gzip
import urllib3
from typing import List, Set, Callable, Any, Dict


from hadi_logger import get_logger
logger = get_logger()
from helpers import *
from progress import  ProgressTracker

global excluded_file, excluded_file_header_written, log_files_data


# Global variables

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FAZapi:

    def __init__(self, base_url:str, options, config:ConfigManager):

        self.base_url = base_url
        self.adom_name = config.adom
        self.devid = config.devid
        self.devtype = config.devtype
        self.session_cookie = None

        self.logtype = options.logtype
        self.query = options.query
        self.startTime = options.st
        self.endTime = options.et
        self.timeout = options.timeout

        self.get_session_cookie()

    def call_FAZ_API(self, body):

        # Make the request to get the session cookie
        try:
            session_resp = requests.post(self.base_url, data=json.dumps(body), verify=False)
            session_resp.raise_for_status()  # Raise an exception for HTTP errors
            if session_resp.status_code != 200:
                logger.error(f"API returned status code {session_resp.status_code}")
                logger.error(f"call_FAZ_API: Response content: {session_resp.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error making request to FortiAnalyzer: {e}")
            return None

                # Rest of your code
        except Exception as e:
            logger.error(f"call_FAZ_API: {str(e)}")
            return None

        return session_resp

    def get_session_cookie(self):
        """
        Authenticates with FortiAnalyzer and retrieves a session cookie.

        Returns:
            str: The session cookie, or None if an error occurs.
        """
        # Authenticate and get session cookie
        logger.debug("Attempting to get session cookie")

        session_file = 'session.key'

        # Try to load existing session
        if os.path.exists(session_file):
            with open(session_file, 'r') as file:
                self.session_cookie = file.readline().strip()

            validate = self.check_session()

            if validate and validate != -11:

                self.close_tid(validate)
                return


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

        session_resp = self.call_FAZ_API(body1)
        # Check if the response is valid JSON and contains the session key

        if session_resp:
            try:
                session_resp_json = session_resp.json()
                if 'session' in session_resp_json:
                    self.session_cookie = session_resp_json["session"]
                    with open('session.key', 'w') as file:
                        file.write(self.session_cookie)
                    logger.debug("Successfully obtained session cookie")
                    #logger.info("Successfully logged in")
                else:
                    logger.error("'session' key not found in the response")
                    #logger.info(f"Full Response from get_session_cookie: {session_resp_json}")
                    return None
            except json.JSONDecodeError:
                logger.error("Error: Session response is not in JSON format")
                #logger.info(f"Full Response Content from get_session_cookie: {session_resp.content}")
                return None


    def check_session(self):
        """
        Starts a log search request with the given query and time range.

        Args:
            query (str): The search query.
            startTime (str): The start time in 'YYYY-MM-DD HH:MM' format.
            endTime (str): The end time in 'YYYY-MM-DD HH:MM' format.

        Returns:
            str: The task ID (tid) of the search request, or None if an error occurs.
        """

        startTime = datetime.now().strftime("%Y-%m-%d %H:%M")
        endTime = datetime.now().strftime("%Y-%m-%d %H:%M")
        body2 = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "add",
            "params": [
                {
                    "apiver": 3,
                    "filter": "",
                    "logtype": "traffic",
                    "device": [{"devid": self.devid}],
                    "time-order": 'desc',
                    "time-range": {"start": startTime, "end": endTime},
                    "url": f"/logview/adom/{self.adom_name}/logsearch",
                }
            ],
            "session": self.session_cookie,
        }

        # Make the request to start the log search

        session_resp = self.call_FAZ_API(body2)

        if session_resp:
            try:
                search_resp_json = session_resp.json()

                if 'result' in search_resp_json:
                    if isinstance(search_resp_json['result'], list) and len(search_resp_json['result']) > 0:
                        if 'status' in search_resp_json['result'][0] and 'code' in search_resp_json['result'][0]['status']:
                            if search_resp_json["result"][0]["status"]["code"] == -11:
                                #logger.info(f"You are logged out. Please login again!")
                                # if args.verbose:
                                #     logger.info(f"Session cookie expired: {search_resp_json['result'][0]['status']['message']}")
                                tid = search_resp_json["result"][0]["status"]["code"]
                            else:
                                tid = search_resp_json["result"].get("tid")
                        else:
                            tid = search_resp_json["result"].get("tid")
                    elif isinstance(search_resp_json['result'], dict):
                        tid = search_resp_json["result"].get("tid")
                    else:
                        logger.error(f"Unexpected 'result' structure: {search_resp_json['result']}")
                        tid = None
                elif 'error' in search_resp_json:
                    message = search_resp_json["error"].get('message', 'Unknown error')
                    # logger.error(f"Invalid command line data: {message}")
                    logger.error(f"Invalid command line data: {search_resp_json.content}")
                    tid = None
                else:
                    logger.error(f"Unexpected response structure: {search_resp_json}")
                    tid = None

            except json.JSONDecodeError:
                logger.error("Request response is not in JSON format")
                #logger.info(f"Full Response Content from check_session: {search_resp_json.content}")
                tid = None

            return tid


    def logout(self):

        request = {
            "method": "exec",
            "params": [
                {
                    "url": "/sys/logout"
                }
            ],
            "session": self.session_cookie,
            "id": 5
        }

        try:
            response = requests.post(self.base_url, json=request, verify=False)

            if response.status_code != 200:
                logger.error(f"API returned status code {response.status_code}")
                logger.error(f"Response content: {response.text}")
                return

        except Exception as e:
            logger.error(f"Error in logout request: {str(e)}")
            return

        try:
            resp_json = response.json()
            if 'result' in resp_json and isinstance(resp_json['result'], list) and len(resp_json['result']) > 0:
                if 'status' in resp_json['result'][0] and 'message' in resp_json['result'][0]['status']:
                    message = resp_json['result'][0]['status']['message']
                    # if args.verbose:
                    #     logger.info(f"Logout successful: {message}")
                else:
                    logger.error("'status' or 'message' not found in the logout response")
                    #logger.info(f"Full Response from check_session: {resp_json}")
            else:
                logger.error("'result' not found or not in expected format in the logout response")
                #logger.info(f"Full Response from check_session: {resp_json}")
        except json.JSONDecodeError:
            logger.error("Logout response is not in JSON format")
            #logger.info(f"Full Response Content from check_session: {response.content}")


    # Function to check if file modification time is greater than 24 hours ago
    def is_old_file(self, file_path):
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

    def list_logfiles(self):


        FAZlogs = 'FAZlogs'
        file_name = 'logfiles.json'
        file_path = os.path.join(FAZlogs, file_name)


        # Check if the file is old or does not exist
        if self.is_old_file(file_path):
            # Call list_logfiles(args.st, args.et) if file is old or does not exist
            logger.info("Updating log files list from FAZ server.")
        else:
            logger.info(f"Skipping list_logfiles since '{file_path}' is recent.")
            return

        body = {
            "id": 5,
            "jsonrpc": "2.0",
            "method": "get",
            "params": [
                {
                    "apiver": 3,
                    "devid": "FV-2KFTE22000040",
                    "url": f"/logview/adom/{self.adom_name}/logfiles/state",
                    "vdom": "root"
                }
            ],
            # "time-range": {"start": startTime, "end": endTime},
            "session": self.session_cookie
        }

        files_list = self.call_FAZ_API(body)

        if files_list:
            files_list_json = files_list.json()
            with open(file_path, 'w') as file:
                file.write(json.dumps(files_list_json, indent=4))
            # print(files_list.content)



    # Assuming you have already defined ADOM_NAME, FORTI, and session_cookie
    def report_download_progress(self, filename, total_size, current_size):
        progress = (current_size / total_size) * 100  # Cap at 100%
        #logger.info(f"Downloading {filename}: {progress:.2f}% complete")
        if current_size >= total_size:
            logger.info(f"Download of {filename} completed.")


    def get_log_file(self, filename, fsize, vdom, max_bytes=None):
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
                        "url": f"/logview/adom/{self.adom_name}/logfiles/data",
                        "devid": self.devid,
                        "vdom": vdom,
                        "filename": filename,
                        "data-type": "csv/gzip/base64",
                        "offset": offset,
                        "length": chunk_size,
                        "apiver": 3
                    }
                ],
                "session": self.session_cookie
            }

            response = self.call_FAZ_API(body)

            if response is None:
                logger.error(f"Failed to retrieve content for {filename}")
                return None
            data = response.json()

            if 'result' not in data or not data['result']:
                break
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
            self.report_download_progress(filename, total_size, offset)

            if offset >= total_size:
                break

        try:
            return all_content.decode('utf-8')
        except UnicodeDecodeError:
            logger.warning(f"UTF-8 decoding failed for {filename}, trying ISO-8859-1")
            return all_content.decode('iso-8859-1')


    def logfields(self, logtype):

        body2 = {
            "id": 4,
            "jsonrpc": "2.0",
            "method": "get",
            "params": [
                {
                    "apiver": 3,
                    "devtype": self.devtype,
                    "logtype": self.logtype,
                    "url": f"/logview/adom/{self.adom_name}/logfields"
                }
            ],
            "session": self.session_cookie,
        }


        fields = self.call_FAZ_API(body2)

        if fields:
            return fields.json()


    # @log_function_details(relevant_globals=['FORTI', "ADOM_NAME", "devid", "session_cookie"])
    def search_request(self, time_order = 'desc'):
        """
        Starts a log search request with the given query and time range.

        Args:
            query (str): The search query.
            startTime (str): The start time in 'YYYY-MM-DD HH:MM' format.
            endTime (str): The end time in 'YYYY-MM-DD HH:MM' format.

        Returns:
            str: The task ID (tid) of the search request, or None if an error occurs.
        """

        body2 = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "add",
            "params": [
                {
                    "apiver": 3,
                    "filter": self.query,
                    "logtype": self.logtype,
                    "device": [{"devid": self.devid}],
                    "time-order": time_order,
                    "time-range": {"start": self.startTime, "end": self.endTime},
                    "url": f"/logview/adom/{self.adom_name}/logsearch",
                }
            ],
            "session": self.session_cookie,
        }

        # Make the request to start the log search

        search_resp = self.call_FAZ_API(body2)

        try:
            search_resp_json = search_resp.json()
            # print(json.dumps(search_resp_json, indent=4))

            if 'result' in search_resp_json and 'tid' in search_resp_json['result']:
                tid = search_resp_json["result"]["tid"]
                # elif search_resp_json["result"][0]["status"]["code"] == -11:
                    # logger.info(f"Session cookie expired: {search_resp_json['result'][0]['status']['message']}")
                    # tid = -11

            elif 'error' in search_resp_json:
                # message = search_resp_json["error"][0]['message']
                message = search_resp_json["error"]['message']
                print_to_console(f"Invalid command line data: {message}")
                tid = None

            else:
                # logger.error("'tid' key not found in the search response")
                logger.error(f"Full Response from search_request: {search_resp_json}")
                tid = None
        except json.JSONDecodeError:
            logger.error("Search response is not in JSON format")
            # logger.info(f"Full Response Content from search_request: {search_resp.content}")
            tid = None

        return tid

    #@log_function_details(relevant_globals=['FORTI', 'ADOM_NAME', 'session_cookie'])
    def close_search_request(self, tid):

        body2 = {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "delete",
                    "params": [
                                {
                                    "apiver": "3",
                                    "url": f"/logview/adom/{self.adom_name}/logsearch/{tid}"
                                }
                            ],
                    "session": self.session_cookie
        }

        # close_resp = requests.post(FORTI, data=json.dumps(body2), verify=False)

        close_resp = self.call_FAZ_API(body2)
        try:
            close_resp_json = close_resp.json()
            if 'result' in close_resp_json and 'status' in close_resp_json['result']:
                message = close_resp_json["result"]["status"]["message"]

            else:
                # logger.error("'tid' key not found in the search response")
                #logger.info(f"Full Response from close_search_request: {close_resp_json}")
                message = None
        except json.JSONDecodeError:
            logger.error(f"Closing search request {tid} response is not in JSON format")
            #logger.info(f"Full Response Content from close_search_request: {close_resp_json.content}")
            message = None

        return message


    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def search_request_status(self, session, tid, offset, limit=1000):

        progress = 0
        stuck_iterations = 0
        max_stuck_iterations = 100  # Reduced to detect stalling faster
        last_progress = -1
        start_time = asyncio.get_event_loop().time()
        timeout = float(self.timeout)  # 5 minutes timeout

        while progress < 100:
            if asyncio.get_event_loop().time() - start_time > timeout:
                logger.warning(f"Timeout reached for TID {tid} and offset {offset}.")
                #logger.info(f"Try again with timeout > the current timeout: (timeout={self.timeout}).")
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
                        "url": f"/logview/adom/{self.adom_name}/logsearch/{tid}"
                    }
                ],
                "session": self.session_cookie,
            }

            try:
                async with session.post(self.base_url, json=body3, ssl=False, timeout=60) as response:
                    try:

                        text = await response.text(encoding='utf-8')
                        results_resp_json = json.loads(text)
                    except UnicodeDecodeError as e:
                        logger.warning(f"UnicodeDecodeError: {e}, trying iso-8859-1 encoding")
                        try:
                            text = await response.text(encoding='iso-8859-1')
                            results_resp_json = json.loads(text)
                        except UnicodeDecodeError as e:
                            logger.error(f"Second UnicodeDecodeError: {e}")
                            raw_content = await response.read()
                            # logger.info(f"Raw response content: {raw_content}")
                            raise
                        except json.JSONDecodeError as e:
                            logger.error(f"JSONDecodeError: {e}")
                            # logger.info(f"Full Response Content from search_request_status (ISO-8859-1 attempt): {text}")
                            raise
                    except json.JSONDecodeError as e:
                        logger.error(f"JSONDecodeError: {e}")
                        # logger.info(f"Full Response Content from search_request_status: {text}")
                        raise

                    try:
                        progress = results_resp_json["result"]["percentage"]

                        if progress == last_progress:
                            stuck_iterations += 1

                            if stuck_iterations >= max_stuck_iterations:
                                # if args.verbose:
                                logger.warning(f"Progress stuck at {progress}% for TID {tid} and offset {offset}. Breaking out of loop.")
                                break
                        else:
                            stuck_iterations = 0
                            last_progress = progress
                        # if args.verbose:
                        #logger.info(f"Progress for TID {tid} and offset {offset}: {progress}%")

                    except KeyError as e:
                        if "error" in results_resp_json:
                            logger.error(f"{results_resp_json['error']['message']}")
                            print_to_console(f"Full Response Content from search_request_status: {json.dumps(results_resp_json, indent=4)}")
                        else:
                            logger.error(f"Unexpected response structure for TID {tid} and offset {offset}: {str(e)}")
                        raise

            except aiohttp.ClientResponseError as e:
                logger.error(f"HTTP error for TID {tid} and offset {offset}: {e.status}")
                raise
            except aiohttp.ClientError as e:
                logger.warning(f"Network error for TID {tid} and offset {offset}: {str(e)}")
                raise

            await asyncio.sleep(2)  # Add a small delay between requests

        return results_resp_json

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def fetch_search_results(self, tids: List[str], total_queries: int, result_processor: Callable) -> int:
        """
        Fetches the search results for the given task IDs with progress tracking.

        Args:
            tids: List of task IDs to fetch results for
            total_queries: Total number of queries being processed
            result_processor: Function to process the results

        Returns:
            int: Total number of results fetched
        """
        total = 0
        queue = asyncio.Queue()
        processed_offsets: Set[tuple] = set()  # Changed to tuple (tid, offset) to track per TID
        offset_lock = asyncio.Lock()
        active_tids = set(tids)

        # Initialize ProgressTracker
        progress_tracker = ProgressTracker(total_queries=len(tids))
        idx_asc = 0  # Assuming this is the starting index, adjust if needed

        async def fetch_results(session: aiohttp.ClientSession, tid: str, offset: int) -> tuple:
            results_resp_json = await self.search_request_status(session, tid, offset)
            return tid, offset, results_resp_json

        async def worker(session: aiohttp.ClientSession) -> None:
            nonlocal total
            while active_tids:
                try:
                    tid, offset = await queue.get()
                    tid_offset_key = (tid, offset)

                    async with offset_lock:
                        if tid_offset_key in processed_offsets:
                            queue.task_done()
                            if tid in active_tids:
                                await queue.put((tid, offset + 1000))
                            continue
                        processed_offsets.add(tid_offset_key)

                    tid, offset_value, results_resp_json = await fetch_results(session, tid, offset)
                    data = results_resp_json.get('result', {}).get('data', [])

                    if data:
                        logger.debug(f"Search status successful for TID: {tid}")
                        try:
                            result_processor(results_resp_json)

                            # Update progress (assuming data contains 'id' field)
                            query_index = tids.index(tid)
                            progress_tracker.update_and_log_progress(query_index, data, idx_asc)

                        except Exception as e:
                            logger.error(f"Error in result_processor for TID {tid}: {e}")

                        return_lines = results_resp_json["result"]["return-lines"]
                        total += return_lines

                        if return_lines == 1000:
                            new_offset = offset + return_lines
                            await queue.put((tid, new_offset))
                        else:
                            active_tids.remove(tid)
                            progress_tracker.next_query()  # Move to next query when complete
                            self.close_tid(tid)  # Close the TID when done
                    else:
                        if tid in active_tids:
                            active_tids.remove(tid)
                            progress_tracker.next_query()
                            self.close_tid(tid)
                            if total == 0:
                                logger.debug(f"No logs found for TID {tid} with the specified criteria.")
                                print_to_console(
                                    f"Full Response Content from fetch_search_results: {json.dumps(results_resp_json, indent=4)}"
                                )

                except json.JSONDecodeError:
                    logger.error(f"Error: Results response is not in JSON format for TID {tid}")
                except Exception as e:
                    logger.error(f"Error occurred while fetching results for TID {tid}: {e}")

                logger.debug(f"Processed - TID: {tid}, Offset: {offset_value}")
                queue.task_done()

        async with aiohttp.ClientSession() as session:
            for tid in tids:
                await queue.put((tid, 0))

            workers = [asyncio.create_task(worker(session)) for _ in range(min(10, len(tids)))]

            await queue.join()

            for w in workers:
                w.cancel()

        return total

    def close_tid(self, tid):
        if tid is None:
            logger.warning("Attempted to close None TID, skipping.")
            return
        try:
            status = self.close_search_request(tid)
            if status == "succeeded":
                # if args.verbose:
                logger.debug(f"Search request {tid} closed successfully.")
            else:
                # if args.verbose:
                logger.warning(f"Failed to close search request {tid}. Status: {status}")
        except Exception as e:
            logger.error(f"Error closing search request {tid}: {str(e)}")

