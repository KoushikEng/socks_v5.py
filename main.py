"""
Main entry point for SOCKSv5 proxy server.

This module initializes logging and starts the SOCKSv5 server.
Run this module to start the proxy server.

Usage:
    python main.py
"""

import argparse
import logging
import sys
import signal

from config import DEFAULT_HOST, DEFAULT_PORT, LOG_LEVEL, LOG_FORMAT, ENABLE_AUTH
from server import Socks5Server

# Global server instance
server = None

def setup_logging():
    """
    Configure logging for the application.

    This function sets up the basic logging configuration with the
    format and level specified in config.py.

    The log format includes: timestamp - log level - message
    """
    logging.basicConfig(
        level=LOG_LEVEL,
        format=LOG_FORMAT
    )
    
def signal_handler(sig, frame):
    """
    Handle termination signals to gracefully shutdown the server.

    Args:
        sig: Signal number
        frame: Current stack frame
    """
    logging.getLogger(__name__).info('Termination signal received, shutting down...')
    if server:
        server.stop()
    
    sys.exit(0)


def main():
    """
    Main function to start the SOCKSv5 proxy server.

    This function:
    1. Parses command line arguments
    2. Sets up logging
    3. Creates a Socks5Server instance with configuration
    4. Starts the server

    The server will run until interrupted with Ctrl+C.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='SOCKS5 Proxy Server')
    parser.add_argument('--host', default=DEFAULT_HOST, 
                       help=f'Host to bind to (default: {DEFAULT_HOST})')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                       help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--auth', action='store_true', default=ENABLE_AUTH,
                       help='Enable username/password authentication')
    
    args = parser.parse_args()
    
    # Step 1: Configure logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Step 2: Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Step 3: Create server instance
    global server
    server = Socks5Server(host=args.host, port=args.port, enable_auth=args.auth)

    # Step 4: Start the server
    # This will block until the server is interrupted
    server.start()


if __name__ == '__main__':
    main()
