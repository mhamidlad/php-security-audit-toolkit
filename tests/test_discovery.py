"""Tests for file discovery."""

from __future__ import annotations

import os
import tempfile

from php_audit.config import ScanConfig
from php_audit.discovery import FileDiscovery


class TestFileDiscovery:
    def test_discovers_php_files(self, tmp_path):
        (tmp_path / "index.php").write_text("<?php echo 'hello';")
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "controller.php").write_text("<?php echo 'hi';")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result["php"]) == 2

    def test_excludes_vendor(self, tmp_path):
        (tmp_path / "index.php").write_text("<?php")
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "autoload.php").write_text("<?php")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        php_files = result["php"]
        assert len(php_files) == 1
        # The only PHP file should be index.php, not vendor/autoload.php
        assert "index.php" in php_files[0]
        assert not any("vendor" in f.replace("\\", "/").split("/") for f in php_files)

    def test_discovers_composer_files(self, tmp_path):
        (tmp_path / "composer.json").write_text('{"require": {}}')
        (tmp_path / "composer.lock").write_text('{"packages": []}')

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result["composer"]) == 2

    def test_discovers_workflow_files(self, tmp_path):
        workflow_dir = tmp_path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        (workflow_dir / "ci.yml").write_text("name: CI\n")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result["workflow"]) == 1

    def test_skips_large_files(self, tmp_path):
        (tmp_path / "big.php").write_text("<?php " + "x" * 2 * 1024 * 1024)

        config = ScanConfig()
        config.max_file_size = 1024  # 1KB
        discovery = FileDiscovery(config)
        result = discovery.discover(str(tmp_path))

        assert len(result["php"]) == 0

    def test_nonexistent_path(self):
        discovery = FileDiscovery(ScanConfig())
        try:
            discovery.discover("/nonexistent/path/12345")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass
