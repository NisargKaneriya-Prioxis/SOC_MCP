import asyncio

from app.monitoring.monitor import (
    SOCMonitor
)


async def main():

    monitor = SOCMonitor(
        worker_count=2
    )

    await monitor.start()


if __name__ == "__main__":
    asyncio.run(main())