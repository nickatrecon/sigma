import logging
import os


def setup_logger(
    name="app", log_file="app.log", console_level=logging.INFO, file_level=logging.DEBUG
):
    """
    Setup a logger that writes to both file and console.

    Args:
        name (str): Name of the logger
        log_file (str): Path to the log file
        console_level: Log level for console output
        file_level: Log level for file output

    Returns:
        logging.Logger: Configured logger instance
    """

    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Create logger if it doesn't exist or get existing one
    logger = logging.getLogger(name)

    # Only configure if it's a new logger (no handlers)
    if not logger.handlers:
        logger.setLevel(min(console_level, file_level))

        # Ensure the log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(file_level)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)

        # Create formatter and add it to handlers
        formatter = logging.Formatter(LOG_FORMAT)
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger
