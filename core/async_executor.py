"""
Async Executor — parallel task execution engine.
Wraps asyncio + ThreadPoolExecutor for running scan tasks concurrently.
"""
import asyncio
import logging
import signal
import functools
from concurrent.futures import ThreadPoolExecutor
from typing import List, Callable, Any, Coroutine, Optional, Dict
from dataclasses import dataclass, field

logger = logging.getLogger('snooger')


@dataclass
class TaskResult:
    """Result of an async task execution."""
    task_name: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration: float = 0.0


class AsyncExecutor:
    """
    High-performance async executor for parallel scanning.
    Supports both coroutines and regular functions (via thread pool).
    """

    def __init__(self, max_concurrent: int = 20, thread_pool_size: int = 10):
        self.max_concurrent = max_concurrent
        self.thread_pool_size = thread_pool_size
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._pool: Optional[ThreadPoolExecutor] = None
        self._cancelled = False
        self._active_tasks: Dict[str, asyncio.Task] = {}

    def _get_pool(self) -> ThreadPoolExecutor:
        if self._pool is None:
            self._pool = ThreadPoolExecutor(
                max_workers=self.thread_pool_size,
                thread_name_prefix='snooger_worker'
            )
        return self._pool

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
        return self._semaphore

    async def run_parallel(self, tasks: List[dict],
                           progress_callback: Optional[Callable] = None) -> List[TaskResult]:
        """
        Run multiple tasks in parallel with concurrency control.

        Each task dict should have:
            - 'name': str — task identifier
            - 'func': Callable — the function to run
            - 'args': tuple — positional args (optional)
            - 'kwargs': dict — keyword args (optional)
        """
        if not tasks:
            return []

        import time
        sem = self._get_semaphore()
        results = []
        completed = 0
        total = len(tasks)

        async def _run_one(task_dict: dict) -> TaskResult:
            nonlocal completed
            name = task_dict.get('name', 'unnamed')
            func = task_dict['func']
            args = task_dict.get('args', ())
            kwargs = task_dict.get('kwargs', {})

            async with sem:
                if self._cancelled:
                    return TaskResult(name, False, error='Cancelled')

                start = time.time()
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(
                            self._get_pool(), functools.partial(func, *args, **kwargs)
                        )

                    duration = time.time() - start
                    completed += 1

                    if progress_callback:
                        progress_callback(completed, total, name)

                    return TaskResult(name, True, result=result, duration=duration)

                except Exception as e:
                    duration = time.time() - start
                    completed += 1
                    logger.error(f"Task '{name}' failed: {e}")
                    return TaskResult(name, False, error=str(e), duration=duration)

        coros = [_run_one(t) for t in tasks]
        results = await asyncio.gather(*coros, return_exceptions=False)
        return results

    async def run_tool(self, cmd: str, timeout: int = 300,
                       cwd: Optional[str] = None) -> tuple:
        """
        Run an external command asynchronously.
        Returns (stdout, stderr, returncode).
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd.split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                return (
                    stdout.decode('utf-8', errors='replace'),
                    stderr.decode('utf-8', errors='replace'),
                    proc.returncode or 0
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.error(f"Command timed out after {timeout}s: {cmd[:80]}")
                return "", f"Timeout after {timeout}s", -1

        except FileNotFoundError as e:
            logger.error(f"Tool not found: {e}")
            return "", str(e), -2
        except Exception as e:
            logger.error(f"Command error: {e}")
            return "", str(e), -3

    async def run_batch_tools(self, commands: List[dict],
                              max_concurrent: int = 5) -> List[TaskResult]:
        """
        Run multiple external commands in parallel.
        Each command dict: {'name': str, 'cmd': str, 'timeout': int, 'cwd': str}
        """
        tasks = []
        for cmd_dict in commands:
            tasks.append({
                'name': cmd_dict.get('name', cmd_dict['cmd'][:40]),
                'func': self.run_tool,
                'args': (cmd_dict['cmd'],),
                'kwargs': {
                    'timeout': cmd_dict.get('timeout', 300),
                    'cwd': cmd_dict.get('cwd'),
                }
            })

        old_max = self.max_concurrent
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

        try:
            return await self.run_parallel(tasks)
        finally:
            self.max_concurrent = old_max
            self._semaphore = asyncio.Semaphore(old_max)

    def cancel_all(self) -> None:
        """Signal all running tasks to cancel."""
        self._cancelled = True
        for name, task in self._active_tasks.items():
            if not task.done():
                task.cancel()
                logger.info(f"Cancelled task: {name}")

    def shutdown(self) -> None:
        """Clean up resources."""
        self._cancelled = False
        if self._pool:
            self._pool.shutdown(wait=False)
            self._pool = None


def run_async(coro: Coroutine) -> Any:
    """
    Helper to run an async function from sync code.
    Creates or gets event loop as needed.
    """
    try:
        loop = asyncio.get_running_loop()
        # If we're already in an async context, create a task
        return asyncio.ensure_future(coro)
    except RuntimeError:
        # No running loop — create one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
