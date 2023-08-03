import os
import logging.handlers
import traceback
logging.raiseExceptions = 1


class LogHelper():
    def __call__(self, log_msg, FileName, log_type):
        pass

    def myLogger(self, log_folder, source):

        f = logging.Formatter("%(asctime)s %(levelname)-9s %(name)-8s %(thread)5s %(message)s")

        root = logging.getLogger(self.SOURCE)

        root.setLevel(logging.INFO)

        log_root = os.path.dirname(__file__)

        source_log = os.path.join(log_root, log_folder)
        is_dir_exist = os.path.exists(source_log)
        if not is_dir_exist:
            os.makedirs(source_log)

        _logFileName = os.path.join(source_log, source + ".log")

        _MaxFileSize = 500000
        _MaxFiles = 50

        h = logging.handlers.RotatingFileHandler(_logFileName, "a", _MaxFileSize, _MaxFiles)
        root.addHandler(h)
        h.setFormatter(f)
        h = logging.handlers.SocketHandler('localhost', logging.handlers.DEFAULT_TCP_LOGGING_PORT)
        root.addHandler(h)

    # ===============================================================================================================================================================
    # Constructor - Logger object created here
    def __init__(self, log_folder, source):
        self.SOURCE = source
        self.LogFolder = log_folder

    # ===============================================================================================================================================================
    # Method to log the error in log file
    def doLog(self, log_msg, log_type):

        logger = logging.getLogger(self.SOURCE)
        if len(logger.handlers) <= 0:
            self.myLogger(self.LogFolder, self.SOURCE)
            logger = logging.getLogger(self.SOURCE)

        strMsg = log_msg

        strMsg = str(strMsg)
        strMsg = "    " + strMsg

        if log_type == 'error':
            strMsg = self.formatExceptionInfo(log_msg)
            logEntry = (40, strMsg)
        elif log_type == 'warn':
            logEntry = (30, strMsg)
        else:
            logEntry = (20, strMsg)

        logger.log(*(logEntry))

    # =============================================================================================================================================================== # Method to reformat the error message in simple readable format
    def formatExceptionInfo(self, objexp):
        maxTBlevel = 1
        eMsg = objexp[1]
        cla, exc, trbk = objexp
        excName = cla.__name__
        try:
            excArgs = exc.__dict__["args"]
        except KeyError:
            excArgs = "<no args>"
        excTb = traceback.format_tb(trbk, maxTBlevel)
        return (excName, excArgs,  excTb, eMsg)
    # ===============================================================================================================================================================
