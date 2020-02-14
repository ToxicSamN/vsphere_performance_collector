import sys
import logging
import logging.handlers


class Logger:
    """
    Custom logging class that fits with how I prefere to log.
    There may be better or more proper ways of doing this but
    this works like a charm.
    This class stores all loggers into a property named loogers.
    A call to get_logger(name) will search for 'name' in loggers
    and if found return that logger, otherwise create a new one.
    """

    # Default log level. This can be changed at initialization of the object
    loglevel = logging.INFO

    def __init__(self, log_file='/var/log/vcenter.log',
                 error_log_file='/var/log/vcenter_err.log',
                 log_size_MB=10, max_logs=8,
                 formatter=logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s"),
                 log_level=logging.INFO):
        self.loggers = {}
        self.log_level = log_level
        self.log_file = log_file
        self.error_log_file = error_log_file

        self.formatter = formatter
        self.logsize = log_size_MB * 1048576
        self.max_logs = max_logs

    def get_logger(self, name):
        """
        Search self.loggers for the 'name' parameter value and if found
        return the already created logger, otherwise create a new one.
        This sets up a file logger for info and error/exception and an
        output stream for debugging. These logger types cannot be changed
        without overriding this method.
        :param name: Name of the logger to be searched for
        :return: logger
        """

        if self.loggers.get(name):
            return self.loggers.get(name)

        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)

        dfh = logging.StreamHandler(stream=sys.stdout)
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(self.formatter)

        lfh = logging.handlers.RotatingFileHandler(self.log_file,
                                                   mode='a',
                                                   maxBytes=self.logsize,
                                                   backupCount=self.max_logs,
                                                   encoding='utf8',
                                                   delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(self.formatter)

        efh = logging.handlers.RotatingFileHandler(self.error_log_file,
                                                   mode='a',
                                                   maxBytes=self.logsize,
                                                   backupCount=self.max_logs,
                                                   encoding='utf8',
                                                   delay=False)
        efh.setLevel(logging.ERROR)
        efh.setFormatter(self.formatter)

        logger.addHandler(lfh)
        logger.addHandler(efh)

        self.loggers.update({name: logger})

        return logger
