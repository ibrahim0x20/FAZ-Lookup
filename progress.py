import time
import sys
from typing import List, Dict, Union, Optional
from hadi_logger import get_logger

logger = get_logger()

from helpers import print_to_console
class ProgressTracker:
    """
    Tracks progress of a process by monitoring changes in ID values.

    This class calculates progress based on ID changes in data records,
    estimates completion time, and displays a console progress bar.
    Compatible with output redirection (e.g., > output.csv).
    """

    def __init__(self, scale: int, bar_width: int = 50):
        """
        Initialize a new ProgressTracker.

        Args:
            idx_asc (int): The index value used for scale calculation.
            bar_width (int): Width of the progress bar in characters.
        """
        self.start_time = time.time()
        self.total_progress = 0.0
        self.last_logged_progress = 0.0
        self.last_logged_time = self.start_time
        self.scale = scale
        self.start_id = None
        self.bar_width = bar_width
        self.last_line_length = 0

        # Keep track of whether progress bar is currently displayed
        self.bar_displayed = False

        # Monkey patch the logger's methods
        self._original_info = logger.info
        self._original_warning = logger.warning
        self._original_error = logger.error
        self._original_debug = logger.debug
        self._original_notice = logger.notice

        logger.info = self._intercept_info
        logger.warning = self._intercept_warning
        logger.error = self._intercept_error
        logger.debug = self._intercept_debug
        logger.notice = self._intercept_notice

    def _clear_progress_bar(self):
        """Clear the progress bar line if it's currently displayed."""
        if self.bar_displayed and self.last_line_length > 0:
            sys.stderr.write('\r' + ' ' * self.last_line_length + '\r')
            sys.stderr.flush()
            self.bar_displayed = False

    def _intercept_info(self, message, *args, **kwargs):
        """Intercept info logs and ensure they appear above the progress bar."""
        self._handle_log(message, self._original_info, *args, **kwargs)

    def _intercept_warning(self, message, *args, **kwargs):
        """Intercept warning logs and ensure they appear above the progress bar."""
        self._handle_log(message, self._original_warning, *args, **kwargs)

    def _intercept_error(self, message, *args, **kwargs):
        """Intercept error logs and ensure they appear above the progress bar."""
        self._handle_log(message, self._original_error, *args, **kwargs)

    def _intercept_debug(self, message, *args, **kwargs):
        """Intercept error logs and ensure they appear above the progress bar."""
        self._handle_log(message, self._original_debug, *args, **kwargs)

    def _intercept_notice(self, message, *args, **kwargs):
        """Intercept error logs and ensure they appear above the progress bar."""
        self._handle_log(message, self._original_notice, *args, **kwargs)

    def _handle_log(self, message, original_log_method, *args, **kwargs):
        """
        Process a log message and ensure it appears above the progress bar.
        1. Clear progress bar if displayed
        2. Log the message
        3. Redraw the progress bar
        """
        # Step 1: Clear the progress bar if it's displayed
        self._clear_progress_bar()

        # Step 2: Log the message (using the original logger method)
        original_log_method(message, *args, **kwargs)

        # Step 3: Redraw the progress bar below the log message
        self._print_progress_bar()

    def _calculate_progress(self, data: List[Dict[str, Union[str, int]]]) -> float:
        """
        Calculate the current progress percentage.

        Args:
            data: List of dictionaries containing ID values.

        Returns:
            float: Progress percentage (0-100).
        """
        if len(data) < 1000:
            return 100.0

        current_id = int(data[-1]['id'])
        progress = min((self.start_id - current_id) / self.scale * 100, 100)
        return progress

    def _format_remaining_time(self) -> str:
        """
        Calculate and format the estimated time remaining.

        Returns:
            str: Formatted time string (HH:MM:SS) or status message.
        """
        current_time = time.time()
        time_elapsed = current_time - self.start_time

        if self.total_progress > 0 and self.total_progress < 100:
            rate_of_progress = self.total_progress / time_elapsed
            time_remaining = (100 - self.total_progress) / rate_of_progress
            return time.strftime('%H:%M:%S', time.gmtime(time_remaining))
        elif self.total_progress >= 100:
            return '00:00:00'
        else:
            return 'calculating...'

    def _get_progress_threshold(self) -> float:
        """
        Determine the threshold for logging progress updates based on current progress.

        Returns:
            float: Threshold value for significant progress change.
        """
        if self.total_progress <= 98.0:
            return 1.0
        elif self.total_progress <= 99.0:
            return 0.01
        else:
            return 0.005

    def _draw_progress_bar(self) -> str:
        """
        Create a string representation of the progress bar.

        Returns:
            str: Formatted progress bar with percentage and time remaining.
        """
        # Calculate how many blocks to fill in the progress bar
        filled_length = int(self.bar_width * self.total_progress / 100)

        # Create the bar with Unicode block characters for a smoother appearance
        bar = '█' * filled_length + '▒' * (self.bar_width - filled_length)

        # Get the time remaining
        time_remaining = self._format_remaining_time()

        # Format the output string
        return f"\r[{bar}] {self.total_progress:.2f}% | ETA: {time_remaining}"

    def _print_progress_bar(self) -> None:
        """
        Print the progress bar to stderr, ensuring it displays even with redirection.
        """
        progress_bar = self._draw_progress_bar()

        sys.stderr.write(progress_bar)
        sys.stderr.flush()

        # Mark that the progress bar is now displayed
        self.bar_displayed = True

        # Store the length for next update
        self.last_line_length = len(progress_bar)

    def update_progress(self, data: List[Dict[str, Union[str, int]]]) -> None:
        """
        Update progress based on the latest data and refresh the progress bar.

        Args:
            data: List of dictionaries containing ID values.

        Raises:
            ValueError: If data is empty or doesn't contain 'id' field.
        """
        if not data:
            # Clear the progress bar before logging a warning
            self._clear_progress_bar()
            logger.warning("Empty data provided to update_progress")
            self._print_progress_bar()
            return

        try:
            # Initialize start_id and scale if not set
            if self.start_id is None:
                self.start_id = int(data[0]['id'])
            #
            # if self.scale is None:
            #     self.scale = self.start_id - int(self.idx_asc)
            #     # We'll let the logger intercept handle this


            # Calculate current progress
            self.total_progress = self._calculate_progress(data)

            # Determine if we should log detailed progress update
            significant_change_threshold = self._get_progress_threshold()
            current_time = time.time()

            # Update the progress bar unless it was just cleared by a log message
            if not self.bar_displayed:
                self._print_progress_bar()
            else:
                # Just update the existing bar
                sys.stderr.write(self._draw_progress_bar())
                sys.stderr.flush()

            # Log additional info if significant progress was made
            if self.total_progress > self.last_logged_progress + significant_change_threshold:
                expected_finish_time = self._format_remaining_time()
                logger.info(f"Progress milestone: {self.total_progress:.2f}%, ETA: {expected_finish_time}")
                self.last_logged_progress = self.total_progress
                self.last_logged_time = current_time

        except (KeyError, ValueError, TypeError) as e:
            # Clear the progress bar before logging an error
            self._clear_progress_bar()
            logger.error(f"Error updating progress: {str(e)}")
            self._print_progress_bar()

    def finish(self) -> None:
        """
        Mark the progress as complete and print a final message.
        """
        # First, restore original logger methods BEFORE final logging
        # This ensures all subsequent logs work normally
        logger.info = self._original_info
        logger.warning = self._original_warning
        logger.error = self._original_error

        # Update progress to 100%
        self.total_progress = 100.0

        # Make sure progress bar is displayed
        if not self.bar_displayed:
            self._print_progress_bar()
        else:
            # Just update the existing bar
            sys.stderr.write(self._draw_progress_bar())
            sys.stderr.flush()

        # Move to the next line after completion
        sys.stderr.write('\n')
        sys.stderr.flush()

        # Mark the bar as no longer displayed
        self.bar_displayed = False

        # Log completion time using the restored original logger
        total_time = time.time() - self.start_time
        logger.info(f"Process completed in {time.strftime('%H:%M:%S', time.gmtime(total_time))}")