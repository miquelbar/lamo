#!/usr/bin/env python3
"""
Unit tests for State & Idempotency Engine (state.py).
Tests SHA-256 step hash calculation, step status resolution, and pipeline filtering.
"""

import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Import state module
import importlib.util
spec = importlib.util.spec_from_file_location("state", str(BASE_DIR / "scripts" / "state.py"))
state_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state_mod)


class TestStateEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.scripts_dir = Path(self.test_dir.name) / "scripts"
        self.scripts_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_calculate_local_hash(self):
        script_file = self.scripts_dir / "sample.sh"
        script_file.write_text("#!/bin/bash\necho 'hello world'\n")

        step_def = {
            "id": "step-test",
            "script": "sample.sh",
        }

        with patch.object(state_mod, "SCRIPTS_DIR", self.scripts_dir):
            h1 = state_mod.calculate_local_hash(step_def)
            self.assertEqual(len(h1), 12)  # 12-char hex prefix

            # Changing content must change hash
            script_file.write_text("#!/bin/bash\necho 'different'\n")
            h2 = state_mod.calculate_local_hash(step_def)
            self.assertNotEqual(h1, h2)

    def test_get_step_status(self):
        step = {"id": "step-test"}

        # 1. Status when no remote record exists -> PENDING
        status = state_mod.get_step_status(step, "abc123456789", None)
        self.assertEqual(status, "PENDING")

        # 2. Status when remote record matches local hash -> COMPLETED
        record_matching = {"status": "COMPLETED", "hash": "abc123456789"}
        status = state_mod.get_step_status(step, "abc123456789", record_matching)
        self.assertEqual(status, "COMPLETED")

        # 3. Status when remote record has different hash -> CHANGED
        record_different = {"status": "COMPLETED", "hash": "oldhash12345"}
        status = state_mod.get_step_status(step, "abc123456789", record_different)
        self.assertEqual(status, "CHANGED")

        # 4. Status when remote record is auto-detected without hash -> COMPLETED (detected)
        record_detected = {"status": "COMPLETED", "detected": True}
        status = state_mod.get_step_status(step, "abc123456789", record_detected)
        self.assertEqual(status, "COMPLETED (detected)")

    def test_is_step_completed(self):
        self.assertTrue(state_mod.is_step_completed("COMPLETED"))
        self.assertTrue(state_mod.is_step_completed("COMPLETED (detected)"))
        self.assertFalse(state_mod.is_step_completed("PENDING"))
        self.assertFalse(state_mod.is_step_completed("CHANGED"))
        self.assertFalse(state_mod.is_step_completed("FAILED"))

    def test_load_config_with_environment_overrides(self):
        with patch.dict(os.environ, {
            "SERVER_IP": "10.20.30.40",
            "ADMIN_USER": "customadmin",
            "SSH_PORT": "3345",
            "NODE_NAME": "worker-x",
            "USER_AUDIT_RETENTION_DAYS": "10",
            "JOURNALD_MAX_USE_MB": "200",
            "DOCKER_LOG_MAX_SIZE": "15m",
            "DOCKER_LOG_MAX_FILES": "4",
            "CONTAINER_RUNTIME": "podman",
        }):
            cfg = state_mod.load_config()
            self.assertEqual(cfg["SERVER_IP"], "10.20.30.40")
            self.assertEqual(cfg["ADMIN_USER"], "customadmin")
            self.assertEqual(cfg["SSH_PORT"], "3345")
            self.assertEqual(cfg["NODE_NAME"], "worker-x")
            self.assertEqual(cfg["USER_AUDIT_RETENTION_DAYS"], "10")
            self.assertEqual(cfg["JOURNALD_MAX_USE_MB"], "200")
            self.assertEqual(cfg["DOCKER_LOG_MAX_SIZE"], "15m")
            self.assertEqual(cfg["DOCKER_LOG_MAX_FILES"], "4")
            self.assertEqual(cfg["CONTAINER_RUNTIME"], "podman")

    def test_step_definitions_include_logging_args(self):
        steps_by_id = {s["id"]: s for s in state_mod.ALL_STEPS}
        self.assertIn("step-docker", steps_by_id)
        self.assertEqual(
            steps_by_id["step-docker"]["args"],
            ["ADMIN_USER", "CONTAINER_RUNTIME"]
        )
        self.assertIn("step-system", steps_by_id)
        self.assertEqual(
            steps_by_id["step-system"]["args"],
            ["SSH_PORT", "USER_AUDIT_RETENTION_DAYS", "JOURNALD_MAX_USE_MB"]
        )
        self.assertIn("step-app-user", steps_by_id)
        self.assertEqual(
            steps_by_id["step-app-user"]["args"],
            ["ADMIN_USER", "DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILES"]
        )

    def test_check_dependencies(self):
        step_with_deps = {
            "id": "step-gateway",
            "depends_on": ["step-docker", "step-app-user"],
        }

        # Missing dependency
        remote_incomplete = {
            "step-docker": {"status": "COMPLETED"},
        }
        ok, err = state_mod.check_dependencies(step_with_deps, remote_incomplete)
        self.assertFalse(ok)
        self.assertIn("step-app-user", err)

        # Incomplete dependency status
        remote_pending = {
            "step-docker": {"status": "COMPLETED"},
            "step-app-user": {"status": "PENDING"},
        }
        ok, err = state_mod.check_dependencies(step_with_deps, remote_pending)
        self.assertFalse(ok)
        self.assertIn("PENDING", err)

        # All dependencies completed
        remote_ready = {
            "step-docker": {"status": "COMPLETED"},
            "step-app-user": {"status": "COMPLETED (detected)"},
        }
        ok, err = state_mod.check_dependencies(step_with_deps, remote_ready)
        self.assertTrue(ok)
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
