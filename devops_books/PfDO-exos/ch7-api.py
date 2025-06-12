"""

Run Graphite beforehand:

docker run -d \
 --name graphite \
 --restart=always \
 -p 80:80 \
 -p 2003-2004:2003-2004 \
 -p 2023-2024:2023-2024 \
 -p 8125:8125/udp \
 -p 8126:8126 \
 graphiteapp/graphite-statsd

 """

from flask import Flask
import logging

from statsd import StatsClient
import random

from functools import wraps

BASE_FORMAT = "[%(name)s][%(levelname)-6s] %(message)s"
FILE_FORMAT = "[%(asctime)s]" + BASE_FORMAT
root_logger = logging.getLogger(__name__)
root_logger.setLevel(logging.DEBUG)
try:
    file_logger = logging.FileHandler('application.log')
except (OSError, IOError):
    file_logger = logging.FileHandler('/tmp/application.log')
file_logger.setLevel(logging.DEBUG)
file_logger.setFormatter(logging.Formatter(FILE_FORMAT))
root_logger.addHandler(file_logger)

logger = root_logger

statsd = StatsClient(host='localhost', port=8125)


def random_exception(wrapped_fun):
    @wraps(wrapped_fun)  # preserves function name & docstring
    def wrapper(*args, **kwargs):
        # logger.info("wrapper is working")  # for demonstration
        if random.randint(1, 1000) % 5 == 0:
            statsd.incr('some.event')
            logger.error("/!\\ error caught !! /!\\")
        return wrapped_fun(*args, **kwargs)
    return wrapper

app = Flask(__name__)

@app.route("/info")
@random_exception
def infolog():
    logger.info("this is an info log")
    return "info"

@app.route("/debug")
@random_exception
def debuglog():
    logger.debug("this is a debug log")
    return "debug"

@app.route("/warning")
@random_exception
def warninglog():
    logger.warning("this is a warning log")
    return "warning"

@app.route("/error")
@random_exception
def errorlog():
    logger.error("this is an error log")
    return "error"
