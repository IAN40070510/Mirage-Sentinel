from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class AuditQueue:
    """Bounded, off-response-path delivery; collector acknowledges only committed inserts."""

    def __init__(self, url: str, token: str, capacity: int = 4096) -> None:
        self.url, self.token = url, token
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(capacity)
        self.dropped = 0
        self.delivered = 0
        self.task: asyncio.Task | None = None

    def emit(self, event: dict) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            logger.error("Forensic queue overflow: dropped=%d", self.dropped)

    async def run(self) -> None:
        async with httpx.AsyncClient(timeout=5) as client:
            while True:
                event = await self.queue.get()
                try:
                    while True:
                        try:
                            result = await client.post(
                                self.url + "/events",
                                json=event,
                                headers={"authorization": "Bearer " + self.token},
                            )
                            result.raise_for_status()
                            self.delivered += 1
                            break
                        except httpx.HTTPError:
                            logger.warning(
                                "Forensic collector unavailable; retrying queued event"
                            )
                            await asyncio.sleep(1)
                finally:
                    self.queue.task_done()

    async def stop(self) -> None:
        try:
            await asyncio.wait_for(self.queue.join(), 5)
        except asyncio.TimeoutError:
            logger.error(
                "Shutdown with %d undelivered forensic events", self.queue.qsize()
            )
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
