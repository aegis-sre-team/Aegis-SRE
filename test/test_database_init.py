import support  # noqa: F401
import os
import tempfile
import unittest
from unittest import mock

from src.db import database
from src.db.models import Base as ModelsBase


class TestInitDbRunsOncePerEngine(unittest.TestCase):
    """Against a remote Postgres, create_all costs seconds (it checks every table), and the dashboard called it
    on every refresh, which made the live page crawl."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(support.restore_default_database)  # runs first (LIFO) so the SQLite file is released

    def _url(self, name):
        return "sqlite:///" + os.path.join(self._dir.name, name).replace("\\", "/")

    def test_repeated_calls_do_not_touch_the_database_again(self):
        database.configure_database(self._url("a.db"))
        with mock.patch.object(ModelsBase.metadata, "create_all", wraps=ModelsBase.metadata.create_all) as create_all:
            database.init_db()
            database.init_db()
            database.init_db()
            self.assertEqual(0, create_all.call_count)

    def test_a_new_engine_is_initialised(self):
        database.configure_database(self._url("a.db"))
        with mock.patch.object(ModelsBase.metadata, "create_all", wraps=ModelsBase.metadata.create_all) as create_all:
            database.configure_database(self._url("b.db"))
            self.assertEqual(1, create_all.call_count)
            database.init_db()
            self.assertEqual(1, create_all.call_count)

    def test_a_failed_attempt_is_retried_next_time(self):
        database.configure_database(self._url("a.db"))
        database._initialized_engine = None  # as if this engine had never been initialised
        with mock.patch.object(ModelsBase.metadata, "create_all", side_effect=[RuntimeError("db down"), None]) as create_all:
            with self.assertRaises(RuntimeError):
                database.init_db()
            database.init_db()
            self.assertEqual(2, create_all.call_count)
            database.init_db()
            self.assertEqual(2, create_all.call_count, "once it succeeds it is remembered")


if __name__ == "__main__":
    unittest.main()
