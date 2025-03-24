import sys
import functools
import inspect
import json
import os
import asyncio
import urllib

from typing import Dict, List, Optional, Any

from hadi_logger import get_logger
logger = get_logger()


header_written = None
idx_asc = 0

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

    if not sys.stdout.isatty():
        print(message, file=sys.stderr, flush=True)
        return
    print(message)


def log_function_details(relevant_globals):
    def decorator_log_details(func):
        @functools.wraps(func)
        def wrapper_log_details(*args, **kwargs):
            # if is_debug_mode():
            log_function_info(func, args, kwargs, relevant_globals)
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper_log_details(*args, **kwargs):
            # if is_debug_mode():
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

            logger.info(f"Function name: {function_name}")

            if sanitized_args:
                logger.info(f"Arguments and their values:")
                for arg, value in sanitized_args.items():
                    logger.info(f"  {arg}: {value}")

            if sanitized_globals:
                logger.info(f"Global variables used in {function_name}:")
                for var, value in sanitized_globals.items():
                    logger.info(f"  {var}: {value}")

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
        logger.error(f"The file '{file_path}' does not exist.")
        return None
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except json.JSONDecodeError:
        logger.error(f"The file '{file_path}' contains invalid JSON.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return None



class ConfigManager:
    """
    A class to manage configuration extraction based on device and log types.
    Properties allow direct access to configuration values (config.devid, config.devtype, etc.)
    """

    def __init__(self, config_file_path: str = 'config.json'):
        """
        Initialize the ConfigManager with a configuration file path.

        Args:
            config_file_path (str): Path to the JSON configuration file.
        """
        self.config_file_path = config_file_path
        self.data = None
        self._device_type = None
        self._log_type = None
        self._device_data = None
        self._load_config()

    def _load_config(self) -> None:
        """
        Load configuration data from the JSON file.
        """
        self.data = read_json(self.config_file_path)
        if not self.data:
            logger.error("Failed to read configuration file")


    def load_config(self, args: Any) -> bool:
        """
        Load configuration for specific device_type and log_type.

        Args:
            args: Object with adom and logtype attributes.

        Returns:
            bool: True if configuration was loaded successfully, False otherwise.
        """
        if not self.data:
            logger.error("No configuration data available")
            return False

        self._device_type = args.adom
        self._log_type = args.logtype

        if self._device_type not in self.data:
            logger.error(f"The device type '{self._device_type}' is not valid. "
                          f"Valid options are: {', '.join(self.data.keys())}.")
            return False

        self._device_data = self.data[self._device_type]

        return True

    @property
    def devid(self) -> Optional[str]:
        """Device ID from the configuration."""
        return self._device_data.get('devid') if self._device_data else None

    @property
    def adom(self) -> Optional[str]:
        """ADOM from the configuration."""
        return self._device_data.get('adom') if self._device_data else None

    @property
    def devtype(self) -> Optional[str]:
        """Device type from the configuration."""
        return self._device_data.get('devtype') if self._device_data else None

    @property
    def fields(self) -> Optional[List]:
        """Fields for the specified log type."""
        if not self._device_data or 'logtype' not in self._device_data:
            return None
        return self._device_data['logtype'].get(self._log_type)


class ResultsPrinter:
    """Class to handle log printing with various output formats."""

    def __init__(self):
        self.header_written = False

    def print_logs(self, results_resp_json: Dict[str, Any], fields: List[str],
                    output_type: str,
                   whitelist_ips: List[str] = None, adom: str = None) -> None:
        """
        Print logs in the specified output format.

        Args:
            results_resp_json: JSON response containing the results
            fields: List of fields to extract from each row
            output_type: Output format ('json', 'csv', or plain text)
            whitelist_ips: Optional list of IPs to exclude
            adom: Optional administrative domain
        """
        if not results_resp_json or "result" not in results_resp_json or "data" not in results_resp_json["result"]:
            logger.warning("Invalid or empty response format")
            return

        # For JSON output, simply print the JSON
        if output_type == 'json':
            print(json.dumps(results_resp_json, indent=4))
            return

        # For CSV or plain text, format the data
        data = results_resp_json["result"]["data"]

        # Print header if not already done
        if not self.header_written:
            sep = ',' if output_type == 'csv' else ' '
            header = sep.join(fields)
            print(header)
            self.header_written = True

        # If no data, log and return
        if not data:
            logger.warning(f"No data returned from the provided query")
            return

        # Process data rows
        self._process_data_rows(data, fields, output_type, whitelist_ips or [], adom)

    def _process_data_rows(self, data: List[Dict[str, Any]], fields: List[str],
                           output_type: str, whitelist_ips: List[str], adom: str) -> None:
        """Process and print data rows in batches."""
        sep = ',' if output_type == 'csv' else ' '
        batch = []

        try:
            for row_data in data:
                # Clean and filter data based on ADOM
                if adom == 'waf':
                    self._clean_waf_data(row_data)
                else:
                    # Skip whitelisted IPs
                    if 'dstip' in row_data and row_data['dstip'] in whitelist_ips:
                        logger.debug(f"Skipping line due to whitelist IP: {row_data['dstip']}")
                        continue
                    self._clean_standard_data(row_data)

                # Format row according to fields
                formatted_row = [str(row_data.get(field, '')) for field in fields]
                batch.append(sep.join(formatted_row))

                # Print in batches of 100 for efficiency
                if len(batch) >= 100:
                    print('\n'.join(batch))
                    batch = []

            # Print any remaining items in batch
            if batch:
                print('\n'.join(batch))

        except IOError as e:
            logger.error(f"I/O error occurred: {e}")
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")

    def _clean_waf_data(self, row_data: Dict[str, Any]) -> None:
        """Clean WAF-specific data fields."""
        if 'http_url' in row_data and row_data['http_url'] is not None:
            row_data['http_url'] = self._clean_url(row_data['http_url'])
        if 'http_agent' in row_data and row_data['http_agent'] is not None and row_data['http_agent'] == '':
            row_data['http_agent'] = self._clean_url(row_data['http_agent'])

    def _clean_standard_data(self, row_data: Dict[str, Any]) -> None:
        """Clean standard data fields."""
        if 'url' in row_data and row_data['url'] != '':
            row_data['url'] = self._clean_url(row_data['url'])
        if 'msg' in row_data and row_data['msg'] != '':
            row_data['msg'] = self._clean_url(row_data['msg'])

    @staticmethod
    def _clean_url(url: str) -> str:
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



