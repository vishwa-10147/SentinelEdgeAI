import asyncio
import logging
from typing import Callable, List, Any, Optional

logger = logging.getLogger(__name__)


class IngestQueue:
    """Async ingestion queue for packet/flow processing.

    Usage:
      q = IngestQueue(process_batch_cb)
      await q.start()
      await q.enqueue(item)
      await q.stop()
    """

    def __init__(
        self,
        process_batch_cb: Callable[[List[Any]], None],
        batch_size: int = 64,
        batch_timeout: float = 0.5,
        max_queue: int = 10000,
    ) -> None:
        self.process_batch_cb = process_batch_cb
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue)
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._task = asyncio.create_task(self._run())
            logger.info("IngestQueue started")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            await self._task
        logger.info("IngestQueue stopped")

    async def enqueue(self, item: Any) -> None:
        await self.queue.put(item)

    async def _run(self) -> None:
        batch: List[Any] = []
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                # gather first item with timeout
                try:
                    item = await asyncio.wait_for(self.queue.get(), timeout=self.batch_timeout)
                    batch.append(item)
                except asyncio.TimeoutError:
                    # timeout — flush if any
                    if batch:
                        await self._process_batch(batch)
                        batch = []
                    continue

                # drain up to batch_size
                while len(batch) < self.batch_size:
                    try:
                        item = self.queue.get_nowait()
                        batch.append(item)
                    except asyncio.QueueEmpty:
                        break

                if batch:
                    await self._process_batch(batch)
                    batch = []

            except Exception:
                logger.exception("Error in ingest queue run loop")

    async def _process_batch(self, batch: List[Any]) -> None:
        try:
            # process_batch_cb may be sync or async
            res = self.process_batch_cb(batch)
            if asyncio.iscoroutine(res):
                await res
        except Exception:
            logger.exception("Error processing batch")
