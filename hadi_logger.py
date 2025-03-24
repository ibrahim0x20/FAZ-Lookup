# -*- coding: utf-8 -*-
#
# HADI-IR Enhanced Logger with Function Details
# Combines HADI-IR Logger with function logging capabilities

import sys
import re
import os
import codecs
import datetime
import traceback
import socket
import logging
import inspect
import threading
import functools
import asyncio
from logging import handlers
from typing import Optional, Callable, Tuple, Any, Union, Dict, List

try:
    import rfc5424logging
    RFC5424_AVAILABLE = True
except ImportError:
    RFC5424_AVAILABLE = False

try:
    from colorama import Fore, Back, Style, init
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


__version__ = '0.3.0'

# Logger Class -----------------------------------------------------------------
class HADILogger:
    """
    HADI-IR Logger for security incident response logging with multiple output options.
    Supports console output with colors, file logging, and remote syslog capabilities.
    """

    # Format types
    STDOUT_CSV = 0
    STDOUT_LINE = 1
    FILE_CSV = 2
    FILE_LINE = 3
    SYSLOG_LINE = 4

    # Log levels mapping
    LEVELS = {
        'debug': 'DEBUG',
        'info': 'INFO',
        'notice': 'NOTICE',
        'warning': 'WARNING',
        'error': 'ERROR',
        'alert': 'ALERT',
        'result': 'RESULT'
    }

    def __init__(self,
                 module_name: str,
                 no_log_file: bool = False,
                 log_file: str = "hadi-ir.log",
                 hostname: str = None,
                 remote_host: Optional[str] = None,
                 remote_port: int = 514,
                 syslog_tcp: bool = False,
                 csv: bool = False,
                 only_relevant: bool = False,
                 debug_mode: bool = False,
                 platform: str = sys.platform,
                 custom_formatter: Optional[Callable] = None):
        """
        Initialize the HADI-IR Logger
        """
        self.module_name = module_name
        self.version = __version__
        self.no_log_file = no_log_file
        self.log_file = log_file
        self.hostname = hostname or socket.gethostname()
        self.csv = csv
        self.only_relevant = only_relevant
        self.debug_mode = debug_mode
        self.custom_formatter = custom_formatter
        self.linesep = "\r\n" if "win" in platform.lower() else "\n"
        self.file_lock = threading.Lock()

        # Statistics
        self.alerts = 0
        self.warnings = 0
        self.notices = 0
        self.messagecount = 0
        self.remote_logging = False

        if not self.no_log_file:
            self._initialize_log_file()

        if COLORAMA_AVAILABLE:
            init(autoreset=True)
        else:
            self.print_to_console("Warning: colorama module not available. Console output will not be colored.")

        if remote_host:
            self._setup_remote_logging(remote_host, remote_port, syslog_tcp)

    def print_to_console(self, message: str) -> None:
        """Print message to console, using stderr if stdout is redirected"""
        if not sys.stdout.isatty():
            print(message, file=sys.stderr, flush=True)
            return
        print(message)

    def _initialize_log_file(self) -> None:
        """Truncate or create the log file at initialization."""
        try:
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            with codecs.open(self.log_file, "w", encoding='utf-8') as logfile:
                logfile.write(f"Log file initialized at {get_syslog_timestamp()}{self.linesep}")
        except Exception as e:
            self.print_to_console(f"Failed to initialize log file {self.log_file}: {str(e)}")
            if self.debug:
                traceback.print_exc()

    def _setup_remote_logging(self, remote_host: str, remote_port: int, syslog_tcp: bool) -> None:
        """Set up remote syslog logging"""
        if not RFC5424_AVAILABLE:
            self.print_to_console('Warning: rfc5424logging module not available. Remote logging disabled.')
            return

        try:
            self.remote_logger = logging.getLogger('HADI-IR')
            self.remote_logger.setLevel(logging.DEBUG)
            socket_type = socket.SOCK_STREAM if syslog_tcp else socket.SOCK_DGRAM
            remote_syslog_handler = rfc5424logging.Rfc5424SysLogHandler(
                address=(remote_host, remote_port),
                facility=handlers.SysLogHandler.LOG_LOCAL3,
                socktype=socket_type
            )
            self.remote_logger.addHandler(remote_syslog_handler)
            self.remote_logging = True
            self.print_to_console(f"Remote logging enabled to {remote_host}:{remote_port} using {'TCP' if syslog_tcp else 'UDP'}")
        except Exception as e:
            self.print_to_console(f'Failed to create remote logger: {str(e)}')
            if self.debug:
                traceback.print_exc()

    def _log(self, level: str, message: str) -> None:
        """
        Internal logging method to handle all log levels
        """
        mes_type = self.LEVELS.get(level.lower(), 'INFO')

        # Get the actual calling module by going back multiple frames
        frame = inspect.currentframe()
        try:
            # Go back one frame to get out of _log
            frame = frame.f_back
            if frame:
                # Go back one more frame to get out of the public logging method (debug, info, etc.)
                frame = frame.f_back
                if frame:
                    module = frame.f_globals.get("__name__", self.module_name)
                else:
                    module = self.module_name
            else:
                module = self.module_name
        except Exception:
            module = self.module_name
        finally:
            # Make sure to delete the frame reference to avoid reference cycles
            del frame

        if not self.debug_mode and mes_type == "DEBUG":
            return

        self._update_counters(mes_type)

        if self.only_relevant and mes_type not in ('ALERT', 'WARNING'):
            return

        if not self.no_log_file:
            self.log_to_file(message, mes_type, module)

        try:
            self.log_to_stdout(message, mes_type)
        except Exception as e:
            self.print_to_console(
                f"Cannot print certain characters to command line - see log file for full unicode encoded log line. Error: {str(e)}")
            if self.debug_mode:
                traceback.print_exc()

        if self.remote_logging:
            self.log_to_remotesys(message, mes_type, module)

    # Public logging methods
    def debug(self, message: str) -> None:
        """Log a debug message"""
        self._log('debug', message)

    def info(self, message: str) -> None:
        """Log an info message"""
        self._log('info', message)

    def notice(self, message: str) -> None:
        """Log a notice message"""
        self._log('notice', message)

    def warning(self, message: str) -> None:
        """Log a warning message"""
        self._log('warning', message)

    def error(self, message: str) -> None:
        """Log an error message"""
        self._log('error', message)

    def alert(self, message: str) -> None:
        """Log an alert message"""
        self._log('alert', message)

    def result(self, message: str) -> None:
        """Log a result message"""
        self._log('result', message)

    def exception(self, message: str, exc_info: Union[tuple, bool] = True) -> None:
        """
        Log an exception with stack trace

        Args:
            message (str): The message to log with the exception
            exc_info (Union[tuple, bool]): Exception info to include. If True, uses current exception
                                         If tuple, should be (type, value, traceback)
        """
        # Get the exception info if True was passed
        if exc_info is True:
            exc_info = sys.exc_info()

        # Format the stack trace if we have exception info
        if exc_info and exc_info != (None, None, None):
            stack_trace = ''.join(traceback.format_exception(*exc_info)).strip()
            full_message = f"{message}\nSTACK TRACE:\n{stack_trace}"
        else:
            full_message = message

        # Log as an ERROR level message
        self._log('error', full_message)

    # Keep the original log method for backward compatibility
    def log(self, mes_type: str, message: str) -> None:
        """Original log method for backward compatibility"""
        self._log(mes_type.lower(), message)

    def _update_counters(self, mes_type: str) -> None:
        """Update message counters based on message type"""
        if mes_type == "ALERT":
            self.alerts += 1
        elif mes_type == "WARNING":
            self.warnings += 1
        elif mes_type == "NOTICE":
            self.notices += 1
        self.messagecount += 1

    def format(self, format_type: int, message: str, *args: Any) -> str:
        """Format log message using custom formatter if provided, otherwise use standard formatting"""
        if not self.custom_formatter:
            return message.format(*args)
        else:
            return self.custom_formatter(format_type, message, args)

    def log_to_stdout(self, message: str, mes_type: str) -> None:
        """Log message to standard output with formatting, ensuring console output"""
        if not COLORAMA_AVAILABLE:
            if self.csv:
                self.print_to_console(f"{get_syslog_timestamp()},{self.hostname},{mes_type},{message}")
            else:
                self.print_to_console(f"{get_syslog_timestamp()} {self.hostname}  {mes_type}: {message}")
            return

        if self.csv:
            formatted = self.format(self.STDOUT_CSV, '{0},{1},{2},{3}', get_syslog_timestamp(), self.hostname, mes_type, message)
            self.print_to_console(formatted)
        else:
            try:
                colors = self._get_colors_for_message_type(mes_type, message)
                base_color, high_color, key_color = colors
                reset_all = Style.RESET_ALL
                formatted_message = self._format_colored_message(message, mes_type, base_color, high_color, key_color)
                self.print_to_console(formatted_message)
            except Exception as e:
                if self.debug_mode:  # Use debug_mode instead of debug
                    traceback.print_exc()
                self.print_to_console(f"Cannot print to cmd line - formatting error: {str(e)}")

    def _get_colors_for_message_type(self, mes_type: str, message: str) -> Tuple[str, str, str]:
        """Get appropriate colors for the message type"""
        key_color = Fore.WHITE
        base_color = Fore.WHITE
        high_color = Fore.WHITE + Back.BLACK

        if mes_type == "NOTICE":
            base_color = Fore.CYAN
            high_color = Fore.BLACK + Back.CYAN
        elif mes_type == "INFO":
            base_color = Fore.GREEN
            high_color = Fore.BLACK + Back.GREEN
        elif mes_type == "WARNING":
            base_color = Fore.YELLOW
            high_color = Fore.BLACK + Back.YELLOW
        elif mes_type == "ALERT":
            base_color = Fore.RED
            high_color = Fore.BLACK + Back.RED
        elif mes_type == "DEBUG":
            base_color = Fore.WHITE
            high_color = Fore.BLACK + Back.WHITE
        elif mes_type == "ERROR":
            base_color = Fore.RED
            high_color = Fore.WHITE + Back.RED
        elif mes_type == "RESULT":
            if "clean" in message.lower():
                high_color = Fore.BLACK + Back.GREEN
                base_color = Fore.GREEN
            elif "suspicious" in message.lower():
                high_color = Fore.BLACK + Back.YELLOW
                base_color = Fore.YELLOW
            else:
                high_color = Fore.BLACK + Back.RED
                base_color = Fore.RED

        return base_color, high_color, key_color

    def _format_colored_message(self, message: str, mes_type: str, base_color: str, high_color: str, key_color: str) -> str:
        """Format message with colors and line breaks"""
        reset_all = Style.RESET_ALL
        type_colorer = re.compile(r'([A-Z]{3,})')
        mes_type = type_colorer.sub(high_color + r'[\1]' + reset_all, mes_type)
        linebreaker = re.compile(r'(MD5:|SHA1:|SHA256:|MATCHES:|FILE:|FIRST_BYTES:|DESCRIPTION:|REASON_[0-9]+)')
        message = linebreaker.sub(r'\n\1', message)
        colorer = re.compile(r'([A-Z_0-9]{2,}:)\s')
        message = colorer.sub(key_color + Style.BRIGHT + r'\1 ' + base_color + Style.NORMAL, message)
        formatted_message = f"{base_color}{message}{reset_all}"
        return f"{reset_all}{mes_type} {formatted_message}"

    def log_to_file(self, message: str, mes_type: str, module: str) -> None:
        """Log message to file in specified format"""
        try:
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            with self.file_lock:
                with codecs.open(self.log_file, "a", encoding='utf-8') as logfile:
                    if self.csv:
                        logfile.write(self.format(
                            self.FILE_CSV,
                            u"{0},{1},{2},{3},{4}{5}",
                            get_syslog_timestamp(),
                            self.hostname,
                            mes_type,
                            module,
                            message,
                            self.linesep
                        ))
                    else:
                        logfile.write(self.format(
                            self.FILE_LINE,
                            u"{0} {1} {2}: {3}: {4}{5}",
                            get_syslog_timestamp(),
                            self.hostname,
                            mes_type.title(),
                            module,
                            message,
                            self.linesep
                        ))
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            self.print_to_console(f"Cannot write to log file {self.log_file}: {str(e)}")

    def log_to_remotesys(self, message: str, mes_type: str, module: str) -> None:
        """Log message to remote syslog server"""
        if not RFC5424_AVAILABLE:
            return

        syslog_message = self.format(
            self.SYSLOG_LINE,
            "{0}: {1}: MODULE: {2} MESSAGE: {3}",
            self.caller if hasattr(self, 'caller') else 'unknown',
            mes_type.title(),
            module,
            message
        )

        try:
            if mes_type == "ALERT":
                self.remote_logger.critical(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "WARNING":
                self.remote_logger.warning(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type in ("NOTICE", "INFO", "RESULT"):
                self.remote_logger.info(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "DEBUG":
                self.remote_logger.debug(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "ERROR":
                self.remote_logger.error(syslog_message, extra={'msgid': str(self.messagecount)})
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            self.print_to_console(f"Error while logging to remote syslog server: {str(e)}")

    def get_stats(self) -> dict:
        """Get logging statistics"""
        return {
            "version": self.version,
            "messages": self.messagecount,
            "alerts": self.alerts,
            "warnings": self.warnings,
            "notices": self.notices
        }

    def log_function_call(self, func_name: str, args_dict: Dict, globals_dict: Dict = None) -> None:
        """
        Log function call details including arguments and relevant global variables
        """
        sanitized_args = self._sanitize_sensitive_values(args_dict)
        message = f"Function call: {func_name}"
        self.debug(message)

        if sanitized_args:
            args_message = "Arguments: " + ", ".join([f"{k}={v}" for k, v in sanitized_args.items()])
            self.debug(args_message)

        if globals_dict:
            sanitized_globals = self._sanitize_sensitive_values(globals_dict)
            globals_message = "Globals: " + ", ".join([f"{k}={v}" for k, v in sanitized_globals.items()])
            self.debug(globals_message)

    def _sanitize_sensitive_values(self, data_dict: Dict) -> Dict:
        """Sanitize sensitive values in a dictionary"""
        sanitized = data_dict.copy()
        sensitive_keys = ['password', 'token', 'api_key', 'secret', 'credential', 'auth']
        for key in sanitized:
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '***REDACTED***'
        return sanitized

def get_syslog_timestamp() -> str:
    """Get current timestamp in syslog format (ISO8601)"""
    date_obj = datetime.datetime.utcnow()
    date_str = date_obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    return date_str

_global_logger = None

def get_logger(**kwargs) -> HADILogger:
    """Get or create a global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = HADILogger(**kwargs)
    return _global_logger

def log_function_details(logger=None, relevant_globals=None):
    """
    Decorator to log function details including arguments and relevant global variables
    """
    if relevant_globals is None:
        relevant_globals = []

    def decorator_log_details(func):
        @functools.wraps(func)
        def wrapper_log_details(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger()

            if logger.debug:
                function_name = func.__name__
                arg_spec = inspect.getfullargspec(func)
                arg_names = arg_spec.args
                all_args = dict(zip(arg_names, args))
                all_args.update(kwargs)
                caller_globals = inspect.currentframe().f_back.f_globals
                global_vars = {var: caller_globals.get(var) for var in relevant_globals if var in caller_globals}
                logger.log_function_call(function_name, all_args, global_vars)

            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper_log_details(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger()

            if logger.debug:
                function_name = func.__name__
                arg_spec = inspect.getfullargspec(func)
                arg_names = arg_spec.args
                all_args = dict(zip(arg_names, args))
                all_args.update(kwargs)
                caller_globals = inspect.currentframe().f_back.f_globals
                global_vars = {var: caller_globals.get(var) for var in relevant_globals if var in caller_globals}
                logger.log_function_call(function_name, all_args, global_vars)

            return await func(*args, **kwargs)

        return async_wrapper_log_details if asyncio.iscoroutinefunction(func) else wrapper_log_details

    return decorator_log_details

def example_custom_formatter(format_type: int, message: str, args: tuple) -> str:
    """Example custom formatter that prefixes messages with a custom tag"""
    formatted = message.format(*args)
    if format_type in (HADILogger.STDOUT_LINE, HADILogger.FILE_LINE, HADILogger.SYSLOG_LINE):
        return f"[CUSTOM] {formatted}"
    return formatted
