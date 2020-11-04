"""
Async tasks that the worker component uses
"""
import datetime
import enum
from uuid import uuid4
import json
from anchore_engine.subsys import logger
from anchore_engine.subsys import metrics
from abc import ABC
from abc import abstractmethod


class Status(enum.Enum):
    pending = 'pending'
    running = 'running'
    failed = 'failed'
    success = 'success'
    complete = 'complete'


class WorkerTask(ABC):
    def __init__(self):
        self.task_id = uuid4().hex
        self.created_at = datetime.datetime.utcnow()
        self.started_at = None
        self.finished_at = None
        self.status = Status.pending

    def _success(self):
        self.status = Status.success
        self.finished_at = datetime.datetime.utcnow()

    def _failed(self):
        self.status = Status.failed
        self.finished_at = datetime.datetime.utcnow()

    def _start(self):
        self.status = Status.running
        self.started_at = datetime.datetime.utcnow()

    def _pre_exec(self):
        self._start()

    @abstractmethod
    def exec(self):
        pass

    def _post_exec(self):
        pass

    def run(self):
        self._pre_exec()
        try:
            self.exec()
        finally:
            self._post_exec()



