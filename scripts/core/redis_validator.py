#!/usr/bin/env python3
"""
Quantum Neural Redis Connectivity Validator for Novamind Digital Twin.

Provides mathematically precise validation of Redis connectivity using
pure Python socket implementation rather than relying on external tools.
This enables proper neurotransmitter pathway testing in the Docker environment.
"""

import logging
import socket
import time
from urllib.parse import urlparse

logger = logging.getLogger("redis_validator")


class RedisValidator:
    """
    Quantum neural validator for Redis connectivity with mathematical precision.
    """

    @staticmethod
    def parse_redis_url(redis_url: str) -> tuple[str, int]:
        """
        Parse Redis URL with neural precision to extract host and port.

        Args:
            redis_url: The Redis URL to parse

        Returns:
            Tuple containing host and port
        """
        # Default Redis port
        default_port = 6379

        if "://" in redis_url:
            # Handle URLs like redis://host:port/db
            parsed = urlparse(redis_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or default_port
        else:
            # Handle simple host:port format
            parts = redis_url.split(":")
            host = parts[0] or "localhost"
            port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else default_port

        return host, port

    @staticmethod
    def check_redis_connectivity(host: str, port: int = 6379, timeout: int = 5) -> bool:
        """
        Check Redis connectivity with quantum-level neural precision.

        Args:
            host: Redis host
            port: Redis port
            timeout: Connection timeout in seconds

        Returns:
            True if Redis is accessible, False otherwise
        """
        try:
            # Create a socket connection to test connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            return result == 0
        except Exception as e:
            logger.warning(f"Error checking Redis connectivity: {e}")
            return False

    @staticmethod
    def wait_for_redis(redis_url: str, max_retries: int = 30, initial_delay: int = 1) -> bool:
        """
        Wait for Redis to become available with exponential backoff.

        Args:
            redis_url: Redis URL
            max_retries: Maximum number of retry attempts
            initial_delay: Initial delay between retries in seconds

        Returns:
            True if Redis became available, False if max retries exceeded
        """
        host, port = RedisValidator.parse_redis_url(redis_url)
        logger.info(f"Waiting for Redis at {host}:{port}...")

        retries = 0
        delay = initial_delay

        while retries < max_retries:
            if RedisValidator.check_redis_connectivity(host, port):
                logger.info(f"Redis is available at {host}:{port}")
                return True

            logger.warning(f"Redis not available at {host}:{port}, retrying in {delay}s...")
            time.sleep(delay)

            # Implement exponential backoff with a cap
            delay = min(delay * 2, 10)
            retries += 1

        logger.error(f"Redis not available at {host}:{port} after {max_retries} retries")
        return False
