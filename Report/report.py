# import time ,datetime
import os,sys
LOG_FILENAME = "../logfile.log"
RECV_IMAGE = ".png"
RECV_AUDIO = ".wav"


from datetime import datetime

def timestamp():
    """Return ISO-like timestamp for logs."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def append_log_to_file(line):
    """Append a log line to disk file for offline inspection."""
    with open(LOG_FILENAME, "a", encoding="utf-8") as f:
        f.write(line + "\n")

