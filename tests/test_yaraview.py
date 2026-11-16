from contextlib import closing, redirect_stdout, redirect_stderr
import io
from pathlib import Path
import pickle
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest

from tools.yaraview import main


class YaraViewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / 'threats.db'
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute('CREATE TABLE dbthreat (id INTEGER PRIMARY KEY, name TEXT, threatObject BLOB)')
            for row_id, name, rules in (
                (1, 'Empty', []),
                (2, 'Trojan:Example', ['rule first { condition: true }', 'rule second { condition: false }']),
                (3, 'Other', ['rule third { condition: true }']),
            ):
                threat = SimpleNamespace(id=100 + row_id, yara_rules=rules)
                connection.execute('INSERT INTO dbthreat VALUES (?, ?, ?)', (row_id, name, pickle.dumps(threat)))
            connection.commit()

    def run_view(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(['--db', str(self.database), *args]), 0)
        return output.getvalue()

    def test_default_and_rule_limit(self):
        self.assertIn('rule third', self.run_view())
        output = self.run_view('--limit', '1', '--check')
        self.assertIn('rule first', output)
        self.assertNotIn('rule second', output)

    def test_filters_and_listing(self):
        output = self.run_view('--name', 'EXAMPLE', '--list')
        self.assertIn('row_id=2 threat_id=102 rules=2', output)
        self.assertNotIn('rule first', output)
        self.assertIn('rule third', self.run_view('--row-id', '3'))
        # SQL metacharacters are literal substring input, not SQL syntax.
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_view('--name', "' OR 1=1 --"), '')

    def test_missing_database_is_not_created(self):
        missing = Path(self.directory.name) / 'missing.db'
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(['--db', str(missing)])
        self.assertEqual(error.exception.code, 1)
        self.assertFalse(missing.exists())

    def test_invalid_limit(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['--limit', '0'])