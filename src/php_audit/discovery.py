"""File discovery for the PHP Security Audit Toolkit."""

from __future__ import annotations

import os
from pathlib import Path

from .config import ScanConfig


# File extensions that the scanner reads
PHP_EXTENSIONS = {".php", ".phtml", ".php5", ".phps"}
CONFIG_EXTENSIONS = {".env", ".ini", ".yml", ".yaml", ".toml", ".conf", ".xml"}
COMPOSER_FILES = {"composer.json", "composer.lock"}
DOCKER_FILES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}
WORKFLOW_DIR = ".github/workflows"


class FileDiscovery:
    """Discovers files to scan in a PHP project."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def discover(self, project_path: str) -> dict[str, list[str]]:
        """Discover files to scan, grouped by category.

        Returns a dict like:
            {
                "php": ["path/to/file.php", ...],
                "composer": ["composer.json", "composer.lock"],
                "config": [".env", "php.ini", ...],
                "docker": ["Dockerfile", "docker-compose.yml", ...],
                "workflow": [".github/workflows/ci.yml", ...],
                "all": [...],  # all discovered files
            }
        """
        root = Path(project_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")
        if not root.is_dir():
            raise NotADirectoryError(f"Project path is not a directory: {project_path}")

        result: dict[str, list[str]] = {
            "php": [],
            "composer": [],
            "config": [],
            "docker": [],
            "workflow": [],
            "all": [],
        }

        for dirpath, dirnames, filenames in os.walk(root):
            # Modify dirnames in-place to skip excluded directories
            dirnames[:] = [
                d for d in dirnames
                if not self._is_excluded_path(os.path.join(dirpath, d))
                and not self._is_symlink_outside(os.path.join(dirpath, d), root)
            ]

            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, root)

                # Skip excluded files
                if self.config.is_excluded(rel_path.replace("\\", "/")):
                    continue

                # Skip files larger than max_file_size
                try:
                    size = os.path.getsize(full_path)
                    if size > self.config.max_file_size:
                        continue
                except OSError:
                    continue

                # Skip symlinks outside root
                if os.path.islink(full_path):
                    if not self.config.follow_symlinks:
                        continue
                    if not self._is_symlink_inside(full_path, root):
                        continue

                lower = filename.lower()

                if lower in COMPOSER_FILES:
                    result["composer"].append(full_path)
                elif lower in DOCKER_FILES or lower == "dockerfile":
                    result["docker"].append(full_path)
                elif PHP_EXTENSIONS.intersection(Path(filename).suffixes):
                    result["php"].append(full_path)
                elif any(filename.endswith(ext) for ext in CONFIG_EXTENSIONS):
                    result["config"].append(full_path)
                elif lower.endswith((".env",)):
                    result["config"].append(full_path)

                result["all"].append(full_path)

        # Also discover workflow files
        workflow_dir = root / WORKFLOW_DIR
        if workflow_dir.exists() and workflow_dir.is_dir():
            for f in workflow_dir.iterdir():
                if f.is_file() and f.suffix in (".yml", ".yaml"):
                    result["workflow"].append(str(f))

        return result

    def _is_excluded_path(self, path: str) -> bool:
        """Check whether a directory path should be excluded."""
        return self.config.is_excluded(path.replace("\\", "/"))

    def _is_symlink_outside(self, path: str, root: Path) -> bool:
        """Check if a symlink points outside the root directory."""
        if not os.path.islink(path):
            return False
        try:
            target = os.path.realpath(path)
            root_resolved = str(root.resolve())
            return not target.startswith(root_resolved)
        except OSError:
            return True

    def _is_symlink_inside(self, path: str, root: Path) -> bool:
        """Check if a symlink target is inside the root directory."""
        return not self._is_symlink_outside(path, root)
