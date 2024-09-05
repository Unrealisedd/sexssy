import multiprocessing
import redis
from rq import Queue

class DistributedScanner:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.redis_conn = redis.Redis(
            host=config['redis']['host'],
            port=config['redis']['port'],
            password=config['redis']['password']
        )
        self.queue = Queue(connection=self.redis_conn)

    def scan(self, scanner, urls):
        jobs = []
        for url in urls:
            job = self.queue.enqueue(scanner.scan_url, url)
            jobs.append(job)

        results = []
        for job in jobs:
            result = job.result
            if result is not None:
                results.append(result)
            else:
                self.logger.error(f"Job failed: {job.exc_info}")

        return results
