import logging
import colorama

# Initialize colorama (required for Windows)
colorama.init()

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.GREEN,
        'CRITICAL': colorama.Fore.RED + colorama.Style.BRIGHT,
    }

    def format(self, record):
        log_message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{log_message}{colorama.Style.RESET_ALL}"

def setup_colored_logging(level=logging.INFO):
    # Get the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove all existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create a new handler
    handler = logging.StreamHandler()

    # Create a formatter
    formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s')

    # Add formatter to handler
    handler.setFormatter(formatter)

    # Add handler to logger
    root_logger.addHandler(handler)