import time
import threading

class RateLimiter:
    """
    Thread-safe Rate Limiter context manager.
    Ensures code block is not executed more than `calls` times in `period` seconds.
    """
    def __init__(self, calls=10, period=60):
        self.calls = calls
        self.period = period
        self.timestamps = []
        self.lock = threading.Lock()

    def __enter__(self):
        with self.lock:
            current_time = time.time()
            
            # Remove timestamps older than the period window
            self.timestamps = [t for t in self.timestamps if current_time - t < self.period]
            
            # If we reached the limit, sleep until the oldest call expires
            if len(self.timestamps) >= self.calls:
                oldest_call = self.timestamps[0]
                sleep_time = self.period - (current_time - oldest_call)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    # Update current time after sleeping
                    current_time = time.time()
            
            # Record execution
            self.timestamps.append(current_time)
            return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass