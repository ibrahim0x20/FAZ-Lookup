import requests
import aiohttp
import asyncio
import json
import time
from datetime import datetime, timedelta
from tenacity import retry, stop_after_attempt, wait_exponential
import urllib3
from typing import List, Set, Callable, Any, Dict, Optional, Union, Tuple
import os
import sys
import getpass

# Import your custom modules
from hadi_logger import get_logger

logger = get_logger()
from helpers import print_to_console, safe_input, ResultsPrinter
from progress import ProgressTracker

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FAZapi:
    """
    Client for interacting with FortiAnalyzer API with optimized async processing.
    """

    def __init__(self, options, config):
        """
        Initialize the FAZapi client.

        Args:
            options: Command line options
            config: Configuration manager
        """
        self.base_url = 'https://' + options.host + '/jsonrpc'
        self.adom_name = config.adom
        self.devid = config.devid
        self.devtype = config.devtype
        self.fields = config.fields
        self.session_cookie = None
        self.session_lock = asyncio.Lock()  # Lock for session management

        # Request parameters
        self.logtype = options.logtype
        self.query = options.query
        self.startTime = options.starttime
        self.endTime = options.endtime
        self.timeout = float(options.timeout)

        # Connection pool settings
        self.max_connections = 20
        self.connection_timeout = 30

        # Call session initialization (assumed to be implemented)
        self.get_session_cookie()

        # Cache for request bodies to avoid repetitive dictionary creation
        self._request_body_cache = {}

        # Find the maximum search index idx_asc for progress tracking purpose
        self.scale = 0
        self.scale = asyncio.run(self.calculate_scale())

    def get_session_cookie(self):
        """
        Authenticates with FortiAnalyzer and retrieves a session cookie.

        Returns:
            str: The session cookie, or None if authentication fails.
        """
        logger.debug("Attempting to get session cookie")
        session_file = 'session.key'

        # Try to load existing session
        if os.path.exists(session_file):
            try:
                with open(session_file, 'r') as file:
                    self.session_cookie = file.readline().strip()

                # Validate existing session
                tid = self.check_session()
                if tid and tid != -11:
                    self.close_tid(tid)
                    return self.session_cookie
            except Exception as e:
                logger.error(f"Error loading session file: {str(e)}")

        # If we get here, we need a new session
        user = safe_input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")

        body = {
            "method": "exec",
            "params": [
                {"url": "/sys/login/user", "data": {"passwd": password, "user": user}}
            ],
            "id": 1,
            "jsonrpc": "2.0"
        }

        try:
            session_resp = self.call_FAZ_API(body)
            if not session_resp:
                logger.error("Failed to get response from FortiAnalyzer API")
                return None

            session_resp_json = session_resp.json()
            if 'session' in session_resp_json:
                self.session_cookie = session_resp_json["session"]
                # Save the session securely
                try:
                    with open(session_file, 'w') as file:
                        file.write(self.session_cookie)
                    os.chmod(session_file, 0o600)  # Set permissions to user read/write only
                    logger.debug("Successfully obtained and saved session cookie")
                    return self.session_cookie
                except Exception as e:
                    logger.error(f"Error saving session file: {str(e)}")
                    return self.session_cookie
            else:
                logger.error(f"'session' key not found in the response: {session_resp_json}")
                return None
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {str(e)}")
            if session_resp:
                logger.debug(f"Response content: {session_resp.text[:200]}...")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in authentication: {str(e)}")
            return None

    def check_session(self):
        """
        Validates the current session by making a simple log search request.

        Returns:
            int/str: The task ID (tid) of the search request if session is valid,
                    -11 if session has expired, or None if an error occurs.
        """
        # Use current time for a minimal search
        current_time = datetime.now()
        startTime = (current_time - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
        endTime = current_time.strftime("%Y-%m-%d %H:%M")

        body = {
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
                    "limit": 1,  # Only need one record to check session
                    "time-range": {"start": startTime, "end": endTime},
                    "url": f"/logview/adom/{self.adom_name}/logsearch",
                }
            ],
            "session": self.session_cookie,
        }

        try:
            session_resp = self.call_FAZ_API(body)
            if not session_resp:
                logger.error("Failed to connect to FortiAnalyzer. Please try again later")
                logger.debug("Failed to get response for session check")

                sys.exit(1)

            search_resp_json = session_resp.json()

            # Check for session expiration
            if 'result' in search_resp_json and isinstance(search_resp_json['result'], list):
                result = search_resp_json['result'][0]
                if 'status' in result and 'code' in result['status']:
                    if result['status']['code'] == -11:
                        logger.info("Session expired. Re-authentication required.")
                        return -11

                    # Return the task ID or appropriate value
                    return result.get("tid")

            # Handle dictionary result case
            elif 'result' in search_resp_json and isinstance(search_resp_json['result'], dict):
                return search_resp_json["result"].get("tid")

            # Handle error case
            elif 'error' in search_resp_json:
                message = search_resp_json["error"].get('message', 'Unknown error')
                logger.error(f"API error: {message}")
                return None

            # Unexpected structure
            else:
                logger.error(f"Unexpected response structure: {search_resp_json}")
                return None

        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {str(e)}")
            if session_resp:
                logger.debug(f"Response content: {session_resp.text[:200]}...")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in session check: {str(e)}")
            return None

    def logout(self):
        """
        Logs out from the FortiAnalyzer API and cleans up the session file.

        Returns:
            bool: True if logout was successful, False otherwise.
        """
        if not self.session_cookie:
            logger.debug("No active session to logout from")
            return True

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
            self.session_cookie = None  # Clear the session even if the request fails

            # Clean up the session file
            if os.path.exists('session.key'):
                try:
                    os.remove('session.key')
                    logger.debug("Session file removed")
                except Exception as e:
                    logger.error(f"Error removing session file: {str(e)}")

            # Check response
            if response.status_code != 200:
                logger.error(f"API returned status code {response.status_code}")
                logger.debug(f"Response content: {response.text[:200]}...")
                return False

            resp_json = response.json()
            if 'result' in resp_json and isinstance(resp_json['result'], list):
                result = resp_json['result'][0]
                if 'status' in result and 'message' in result['status']:
                    logger.debug(f"Logout successful: {result['status']['message']}")
                    return True

            logger.warning("Unexpected response format during logout")
            return True  # Session is cleared locally even if response is unexpected

        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error in logout request: {str(e)}")
            return False

    async def call_FAZ_API_async(self, body: Dict, session: Optional[aiohttp.ClientSession] = None) -> Dict:
        """
        Make an async request to the FortiAnalyzer API.

        Args:
            body: Request body
            session: Optional existing aiohttp ClientSession

        Returns:
            Dict: Response data or None on error
        """
        own_session = False
        if session is None:
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.max_connections, ssl=False))
            own_session = True

        try:
            async with session.post(
                    self.base_url,
                    json=body,
                    ssl=False,
                    timeout=self.connection_timeout
            ) as response:
                if response.status != 200:
                    logger.error(f"API returned status code {response.status}")
                    return None

                text = await response.text(encoding='utf-8')
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    logger.error("Response is not in valid JSON format")
                    return None

        except aiohttp.ClientError as e:
            logger.error(f"Error making async request to FortiAnalyzer: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in call_FAZ_API_async: {str(e)}")
            return None
        finally:
            if own_session:
                await session.close()

    def call_FAZ_API(self, body: Dict) -> Optional[requests.Response]:
        """
        Make a synchronous request to the FortiAnalyzer API.

        Args:
            body: Request body

        Returns:
            requests.Response or None on error
        """
        try:
            # Use a session with connection pooling for better performance
            with requests.Session() as session:
                session.verify = False
                session.headers.update({
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                })

                response = session.post(
                    self.base_url,
                    json=body,
                    timeout=self.connection_timeout
                )
                response.raise_for_status()
                return response

        except requests.exceptions.RequestException as e:
            logger.debug(f"Error making request to FortiAnalyzer: {e}")
            return None
        except Exception as e:
            logger.error(f"call_FAZ_API: {str(e)}")
            return None

    def _get_request_body(self, method: str, params: List[Dict]) -> Dict:
        """
        Create a request body with cached templates for better performance.

        Args:
            method: API method (add, get, delete)
            params: Parameters for the request

        Returns:
            Dict: Request body
        """
        # Add this check at the beginning of the method
        if not hasattr(self, '_request_body_cache') or self._request_body_cache is None:
            self._request_body_cache = {}
        # Create a cache key based on the method
        cache_key = method

        if cache_key not in self._request_body_cache:
            # Create the base request body and cache it
            self._request_body_cache[cache_key] = {
                "id": hash(method) % 1000,  # Use a deterministic ID
                "jsonrpc": "2.0",
                "method": method
            }

        # Create a copy of the cached body and add dynamic parts
        body = self._request_body_cache[cache_key].copy()
        body["params"] = params
        body["session"] = self.session_cookie

        return body

    async def refresh_session_if_needed(self, session: aiohttp.ClientSession) -> bool:
        """
        Check and refresh the session cookie if expired.

        Args:
            session: aiohttp ClientSession

        Returns:
            bool: True if session is valid, False otherwise
        """
        # This would need to be implemented based on your session handling logic
        # Placeholder for the concept
        async with self.session_lock:
            if self.session_cookie is None:
                # Refresh session logic would go here
                self.get_session_cookie()
                return self.session_cookie is not None
            return True

    def search_request(self, time_order: str = 'desc') -> Optional[str]:
        """
        Start a log search request with the given parameters.

        Args:
            time_order: Order of results by time ('desc' or 'asc')

        Returns:
            str: Task ID (tid) or None on error
        """
        params = [{
            "apiver": 3,
            "filter": self.query,
            "logtype": self.logtype,
            "device": [{"devid": self.devid}],
            "time-order": time_order,
            "time-range": {"start": self.startTime, "end": self.endTime},
            "url": f"/logview/adom/{self.adom_name}/logsearch",
        }]

        body = self._get_request_body("add", params)
        search_resp = self.call_FAZ_API(body)

        if not search_resp:
            return None

        try:
            search_resp_json = search_resp.json()

            if 'result' in search_resp_json and 'tid' in search_resp_json['result']:
                return search_resp_json["result"]["tid"]
            elif 'error' in search_resp_json:
                message = search_resp_json["error"].get('message', 'Unknown error')
                print_to_console(f"Invalid command line data: {message}")
                return None
            else:
                logger.error(f"Unexpected response structure: {search_resp_json}")
                return None

        except json.JSONDecodeError:
            logger.error("Search response is not in JSON format")
            return None

    def close_search_request(self, tid: str) -> Optional[str]:
        """
        Close a search request by its task ID.

        Args:
            tid: Task ID to close

        Returns:
            str: Status message or None on error
        """
        params = [{
            "apiver": "3",
            "url": f"/logview/adom/{self.adom_name}/logsearch/{tid}"
        }]

        body = self._get_request_body("delete", params)
        close_resp = self.call_FAZ_API(body)

        if not close_resp:
            return None

        try:
            close_resp_json = close_resp.json()
            if 'result' in close_resp_json and 'status' in close_resp_json['result']:
                return close_resp_json["result"]["status"]["message"]
            else:
                return None

        except json.JSONDecodeError:
            logger.error(f"Closing search request {tid} response is not in JSON format")
            return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def search_request_status(self, session: aiohttp.ClientSession, tid: str,
                                    offset: int = 0, limit: int = 1000) -> Dict:
        """
        Check the status of a search request.

        Args:
            session: aiohttp ClientSession
            tid: Task ID to check
            offset: Result offset
            limit: Maximum number of results to return

        Returns:
            Dict: Response data
        """
        # Add this check at the beginning of the method
        if not hasattr(self, '_request_body_cache') or self._request_body_cache is None:
            self._request_body_cache = {}
        start_time = asyncio.get_event_loop().time()
        progress = 0
        stuck_iterations = 0
        max_stuck_iterations = 50  # Detect stalling faster
        last_progress = -1

        while progress < 100:
            # Check timeout
            if asyncio.get_event_loop().time() - start_time > self.timeout:
                logger.warning(f"Timeout reached for TID {tid} and offset {offset}.")
                break

            # Ensure session is valid
            if not await self.refresh_session_if_needed(session):
                logger.error("Failed to refresh session")
                raise Exception("Session refresh failed")

            params = [{
                "apiver": 3,
                "limit": limit,
                "offset": offset,
                "url": f"/logview/adom/{self.adom_name}/logsearch/{tid}"
            }]

            body = self._get_request_body("get", params)

            try:
                # More efficient to use json parameter directly
                async with session.post(self.base_url, json=body, ssl=False, timeout=60) as response:
                    try:
                        # Try to decode as UTF-8 first
                        text = await response.text(encoding='utf-8')
                        results_resp_json = json.loads(text)
                    except UnicodeDecodeError:
                        # Fall back to ISO-8859-1 if UTF-8 fails
                        logger.warning("UnicodeDecodeError with UTF-8, trying ISO-8859-1")
                        text = await response.text(encoding='iso-8859-1')
                        results_resp_json = json.loads(text)

                    # Check progress
                    try:
                        progress = results_resp_json["result"]["percentage"]

                        # Handle stuck progress
                        if progress == last_progress:
                            stuck_iterations += 1
                            if stuck_iterations >= max_stuck_iterations:
                                logger.warning(f"Progress stuck at {progress}% for TID {tid}. Breaking out of loop.")
                                break
                        else:
                            stuck_iterations = 0
                            last_progress = progress

                    except KeyError:
                        if "error" in results_resp_json:
                            logger.error(f"API error: {results_resp_json['error'].get('message', 'Unknown error')}")
                        else:
                            logger.error(f"Unexpected response structure for TID {tid}")
                        raise

            except (aiohttp.ClientResponseError, aiohttp.ClientError) as e:
                logger.error(f"Network error for TID {tid}: {str(e)}")
                raise

            # Use exponential backoff with jitter
            delay = 1 + (stuck_iterations * 0.2)
            await asyncio.sleep(min(delay, 5))  # Cap at 5 seconds

        return results_resp_json

    async def fetch_search_results(self, tids: List[str], total_queries: int,
                                   result_processor: Callable) -> int:
        """
        Optimized version using producer-consumer pattern with bounded semaphore.

        Args:
            tids: List of task IDs to fetch results for
            total_queries: Total number of queries being processed
            result_processor: Function to process the results

        Returns:
            int: Total number of results fetched
        """
        if not tids:
            logger.warning("No task IDs provided to fetch_search_results")
            return 0

        # Shared state
        total = 0
        results_lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(min(20, len(tids) * 2))  # Bounded concurrency
        active_tids = set(tids)
        processed_cache = {}  # Track processed (tid, offset) pairs

        # Initialize progress tracking
        progress_tracker = ProgressTracker(self.scale)

        # Task tracking for faster completion detection
        pending_tasks = set()

        async def process_chunk(session: aiohttp.ClientSession, tid: str, offset: int):
            """Process a single chunk of results."""
            nonlocal total

            # Check if already processed
            cache_key = (tid, offset)
            if cache_key in processed_cache:
                return

            processed_cache[cache_key] = True

            try:
                # Get results with retry logic
                results = await self.search_request_status(session, tid, offset)

                data = results.get('result', {}).get('data', [])
                if not data:
                    # No data in this chunk
                    if tid in active_tids:
                        active_tids.remove(tid)
                        # progress_tracker.next_query()
                        self.close_tid(tid)
                        if total == 0:
                            logger.debug(f"No logs found for TID {tid}")
                    return

                # Process the results
                query_index = tids.index(tid)
                try:
                    # Apply result processor
                    result_processor(results)

                    # Update progress
                    progress_tracker.update_progress(data)

                    # Update total count
                    return_lines = results["result"]["return-lines"]
                    async with results_lock:
                        total += return_lines

                    # Schedule next chunk if needed
                    if return_lines == 1000:
                        task = asyncio.create_task(
                            bounded_process_chunk(session, tid, offset + return_lines)
                        )
                        pending_tasks.add(task)
                        task.add_done_callback(pending_tasks.discard)
                    else:
                        # This TID is complete
                        if tid in active_tids:
                            active_tids.remove(tid)
                            # progress_tracker.next_query()
                            self.close_tid(tid)

                except Exception as e:
                    logger.error(f"Error processing results for TID {tid}: {e}")

            except Exception as e:
                logger.error(f"Error fetching results for TID {tid}, offset {offset}: {e}")

        async def bounded_process_chunk(session, tid, offset):
            """Process a chunk with concurrency control."""
            async with semaphore:
                await process_chunk(session, tid, offset)

        async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=self.max_connections, ssl=False),
                timeout=aiohttp.ClientTimeout(total=self.timeout * 1.5)
        ) as session:
            # Start initial processing for each TID
            for tid in tids:
                task = asyncio.create_task(bounded_process_chunk(session, tid, 0))
                pending_tasks.add(task)
                task.add_done_callback(pending_tasks.discard)

            # Wait for all tasks to complete
            while pending_tasks:
                done, _ = await asyncio.wait(
                    pending_tasks,
                    timeout=5,  # Check periodically to handle new tasks
                    return_when=asyncio.FIRST_COMPLETED
                )

                # Early exit if no more active TIDs
                if not active_tids and not pending_tasks:
                    break
        progress_tracker.finish()
        return total

    def close_tid(self, tid: str) -> None:
        """
        Close a task by its ID.

        Args:
            tid: Task ID to close
        """
        if tid is None:
            logger.warning("Attempted to close None TID, skipping.")
            return

        try:
            status = self.close_search_request(tid)
            if status == "succeeded":
                logger.debug(f"Search request {tid} closed successfully.")
            else:
                logger.warning(f"Failed to close search request {tid}. Status: {status}")
        except Exception as e:
            logger.error(f"Error closing search request {tid}: {str(e)}")

    # Method to batch process multiple TIDs in parallel
    async def batch_process_tids(self, queries: List[Dict],
                                 result_processor: Callable) -> Dict[str, int]:
        """
        Process multiple queries in parallel batches.

        Args:
            queries: List of query dictionaries
            result_processor: Function to process results

        Returns:
            Dict: Mapping of query identifiers to result counts
        """
        results = {}

        # Create all TIDs first
        tids = []
        for query in queries:
            # Set temporary query parameters
            orig_query = self.query
            orig_st = self.startTime
            orig_et = self.endTime

            try:
                self.query = query.get('filter', self.query)
                self.startTime = query.get('start', self.startTime)
                self.endTime = query.get('end', self.endTime)

                tid = self.search_request()
                if tid:
                    tids.append((tid, query.get('id', str(len(tids)))))
            finally:
                # Restore original parameters
                self.query = orig_query
                self.startTime = orig_st
                self.endTime = orig_et

        # Process all TIDs in batches
        batch_size = min(5, len(tids))
        for i in range(0, len(tids), batch_size):
            batch = tids[i:i + batch_size]
            batch_tids = [t[0] for t in batch]
            batch_ids = [t[1] for t in batch]

            # Create a result processor that tracks which query produced which results
            batch_results = {}

            def batch_processor(results_json):
                tid = results_json.get('tid')
                if tid:
                    idx = batch_tids.index(tid) if tid in batch_tids else -1
                    if idx >= 0:
                        query_id = batch_ids[idx]
                        # Call original processor with query ID context
                        result_processor(results_json, query_id)

            total = await self.fetch_search_results(batch_tids, len(batch_tids), batch_processor)

            # Record results for this batch
            for tid, query_id in zip(batch_tids, batch_ids):
                results[query_id] = total / len(batch_tids)  # Estimate

        return results

    async def calculate_scale(self, retry_count=0, max_retries=3) -> Optional[int]:
        """Get the scale (difference between descending and ascending log indices) in the given time range.

        Implements retry logic with a maximum of 3 attempts if calculation fails.

        Returns:
            Optional[int]: Scale value if successful, None otherwise
        """
        if retry_count >= max_retries:
            logger.error(f"Failed to calculate scale after {max_retries} attempts")
            return None

        try:
            async with aiohttp.ClientSession() as session:
                # Get ascending index
                idx_asc = None
                tid_asc = self.search_request('asc')
                if not tid_asc:
                    logger.error("Failed to create ascending search request")
                else:
                    try:
                        results_resp_asc = await self.search_request_status(session, tid_asc)
                        if results_resp_asc.get('result', {}).get('data', []):
                            idx_asc = results_resp_asc["result"]['data'][0]['id']
                            logger.debug(f"Start logs index (ascending): {idx_asc}")
                        else:
                            logger.info("No data found in ascending search results")
                            # Early exit on this specific warning
                            sys.exit(0)
                    except KeyError:
                        if "error" in results_resp_asc:
                            logger.error(f"Ascending search error: {results_resp_asc['error']['message']}")
                        else:
                            logger.error(f"Unexpected ascending response structure: {results_resp_asc}")
                    except Exception as e:
                        logger.error(f"Error in ascending search: {str(e)}")
                    finally:
                        if tid_asc:
                            self.close_tid(tid_asc)

                # Get descending index
                idx_desc = None
                tid_desc = self.search_request('desc')
                if not tid_desc:
                    logger.error("Failed to create descending search request")
                else:
                    try:
                        results_resp_desc = await self.search_request_status(session, tid_desc)
                        if results_resp_desc.get('result', {}).get('data', []):
                            idx_desc = results_resp_desc["result"]['data'][0]['id']
                            logger.debug(f"End logs index (descending): {idx_desc}")
                        else:
                            logger.info("No data found in descending search results")
                            # Early exit on this specific warning
                            sys.exit(0)
                    except KeyError:
                        if "error" in results_resp_desc:
                            logger.error(f"Descending search error: {results_resp_desc['error']['message']}")
                        else:
                            logger.error(f"Unexpected descending response structure: {results_resp_desc}")
                    except Exception as e:
                        logger.error(f"Error in descending search: {str(e)}")
                    finally:
                        if tid_desc:
                            self.close_tid(tid_desc)

                # Calculate scale if both indices are available
                if idx_asc is not None and idx_desc is not None:
                    try:
                        scale = int(idx_desc) - int(idx_asc)
                        if scale >= 0:
                            return scale
                        else:
                            logger.warning(f"Negative scale calculated: {scale}")
                            logger.info(f"idx_desc = {idx_desc}, idx_asc = {idx_asc}")
                            # Retry with recursive call
                            return await self.calculate_scale(retry_count + 1, max_retries)
                    except ValueError as e:
                        logger.error(f"Error converting indices to integers: {str(e)}")

            # If we get here, something failed
            logger.warning(f"Retrying calculate_scale (attempt {retry_count + 1}/{max_retries})")
            return await self.calculate_scale(retry_count + 1, max_retries)

        except Exception as e:
            logger.error(f"Unexpected error in calculate_scale: {str(e)}")
            return await self.calculate_scale(retry_count + 1, max_retries)


    # def search(self, output_type: str, whitelist_ips: List[str] = None) -> int:
    def search(self, callback) -> int:
        # Initialize the log printer
        # log_printer = ResultsPrinter()
        #
        # # Create a callback function that uses the log_printer
        # def callback(results_resp_json):
        #     log_printer.print_logs(
        #         results_resp_json,
        #         self.fields,
        #         output_type,
        #         whitelist_ips,
        #         self.adom_name
        #     )

        # Generate search requests and filter valid ones
        tids = []
        for _ in range(10):
            tid = self.search_request()
            if tid is not None and tid != -11:
                tids.append(tid)

        # Run the async function in a new event loop
        total = asyncio.run(self.fetch_search_results(tids, len(tids), callback))

        return total

