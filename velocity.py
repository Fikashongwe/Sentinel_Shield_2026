import time
from collections import deque
import logging

class FileVelocityMonitor:
    def __init__(self, max_changes: int = 20, time_window: float = 3.0):
        """
        Tracks file modification frequency.
        :param max_changes: Threshold of changes allowed within the window.
        :param time_window: Rolling window duration in seconds.
        """
        self.max_changes = max_changes
        self.time_window = time_window
        self.event_timestamps = deque()

    def register_event(self, file_path: str) -> bool:
        """
        Registers a file system event and checks against velocity limits.
        Returns True if an anomaly (velocity spike) is detected.
        """
        current_time = time.time()
        self.event_timestamps.append(current_time)

        # Drop timestamps older than the rolling window
        while self.event_timestamps and self.event_timestamps[0] < current_time - self.time_window:
            self.event_timestamps.popleft()

        # Check if the rate exceeds the threshold
        if len(self.event_timestamps) >= self.max_changes:
            logging.warning(f"Velocity spike detected! {len(self.event_timestamps)} events recorded within {self.time_window}s. Latest file: {file_path}")
            return True

        return False