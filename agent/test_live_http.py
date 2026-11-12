"""Local response-saving fixtures; no target or model calls."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest
import live_http


class ResponseStorageTests(unittest.TestCase):
    def test_saved_body_keeps_report_space_and_old_file_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(live_http, 'WORK_DIRECTORY', Path(tmp)):
            path = Path(tmp) / 'response.txt'
            path.write_text('old evidence')
            with patch.object(live_http.shutil, 'disk_usage', return_value=SimpleNamespace(free=live_http.REPORT_RESERVE_BYTES + 3)):
                reply = live_http.save_body(path, 'new response')
            self.assertEqual(reply['save_body_error'], 'report_space_reserved')
            self.assertEqual(path.read_text(), 'old evidence')
            with patch.object(live_http.shutil, 'disk_usage', return_value=SimpleNamespace(free=live_http.REPORT_RESERVE_BYTES + 100)):
                self.assertIn('saved_body', live_http.save_body(path, 'new response'))
            self.assertEqual(path.read_text(), 'new response')
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_external_paths_and_links_are_not_written(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            path = Path(outside) / 'outside.txt'
            path.write_text('original')
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with patch.object(live_http, 'WORK_DIRECTORY', Path(tmp)):
                self.assertEqual(live_http.save_body(link, 'replacement')['save_body_error'], 'outside_work_directory')
                self.assertEqual(live_http.save_body(tmp, 'replacement')['save_body_error'], 'outside_work_directory')
            self.assertEqual(path.read_text(), 'original')
