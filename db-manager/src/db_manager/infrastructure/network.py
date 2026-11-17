# SPDX-License-Identifier: GPL-3.0-or-later

"""Provide asynchronous request throttling and retry behavior.

Coordinate request starts and apply bounded delays after retryable failures.
"""

import asyncio
import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Self

import httpx2

from db_manager.constants import (
    HTTP_RETRY_BACKOFF_BASE_SECONDS,
    HTTP_RETRY_MAX_BACKOFF_SECONDS,
    HTTP_RETRY_STATUSES,
    MAX_HTTP_RETRIES,
)


def _exponential_backoff(attempt: int) -> float:
    """Return a bounded exponential retry delay.

    Args:
        attempt: Zero-based retry number.

    Returns:
        Delay in seconds, capped at the configured maximum.
    """
    return float(
        min(
            HTTP_RETRY_MAX_BACKOFF_SECONDS,
            HTTP_RETRY_BACKOFF_BASE_SECONDS**attempt,
        )
    )


class AsyncRateLimiter:
    """Space request starts without blocking the event loop.

    Attributes:
        interval: Minimum delay between request starts, in seconds.
        _lock: Serializes reservations for upcoming request starts.
        _next_request_at: Monotonic time when the next request may start.
    """

    def __init__(self: Self, interval: float) -> None:
        """Initialize a request-start limiter.

        Args:
            interval: Minimum delay between request starts, in seconds.

        Raises:
            ValueError: If the interval is not positive.
        """
        if interval <= 0:
            message = "Rate limit interval must be positive"
            raise ValueError(message)
        self.interval = interval
        self._lock = asyncio.Lock()
        self._next_request_at = 0.0

    async def wait(self: Self) -> None:
        """Wait until the next request may start.

        Reserve the next start time while holding the shared limiter lock.
        """
        loop = asyncio.get_running_loop()
        async with self._lock:
            delay = self._next_request_at - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next_request_at = loop.time() + self.interval


def _retry_delay(response: httpx2.Response, attempt: int) -> float:
    """Return the server's requested retry delay or exponential backoff.

    Args:
        response: Response that triggered a retry.
        attempt: Zero-based retry number.

    Returns:
        Non-negative delay in seconds.
    """
    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            delay = float(retry_after)
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(retry_after)
            except (TypeError, ValueError, OverflowError):
                retry_at = None
            if retry_at is not None:
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=UTC)
                delay = (retry_at - datetime.now(UTC)).total_seconds()
            else:
                delay = -1.0
        if math.isfinite(delay) and delay >= 0:
            return delay
    return _exponential_backoff(attempt)


async def get_with_retries(
    client: httpx2.AsyncClient,
    url: str,
    rate_limiter: AsyncRateLimiter,
    headers: dict[str, str] | None = None,
) -> httpx2.Response:
    """Send an asynchronous GET with bounded, rate-limited retries.

    Args:
        client: Shared asynchronous HTTP client.
        url: Resource URL.
        rate_limiter: Per-service request-start limiter.
        headers: Optional request-specific headers.

    Returns:
        HTTP response, including a final non-success response.

    Raises:
        httpx2.TimeoutException: If every request attempt times out.
        httpx2.HTTPError: If another transport error occurs.
    """
    attempt = 0
    while True:
        await rate_limiter.wait()
        try:
            response = await client.get(url, headers=headers)
        except httpx2.TimeoutException:
            if attempt >= MAX_HTTP_RETRIES:
                raise
            await asyncio.sleep(_exponential_backoff(attempt))
            attempt += 1
            continue
        if (
            response.status_code not in HTTP_RETRY_STATUSES
            or attempt >= MAX_HTTP_RETRIES
        ):
            return response
        await asyncio.sleep(_retry_delay(response, attempt))
        attempt += 1
