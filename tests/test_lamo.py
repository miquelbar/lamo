#!/usr/bin/env python3
"""
Unit tests for Lamo (L'Amo) Multi-Server Orchestrator CLI.
Tests configuration parsing, multi-server node registry, active node resolution,
and argument parser routing.
"""

import sys
import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Import functions from lamo script
import importlib.util
from importlib.machinery import SourceFileLoader

loader = SourceFileLoader("lamo", str(BASE_DIR / "lamo"))
spec = importlib.util.spec_from_loader("lamo", loader)
lamo_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lamo_mod)


class TestLamoConfigAndNodes(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_path = Path(self.test_dir.name)
        self.config_file = self.test_path / "config.env"
        self.nodes_file = self.test_path / "nodes.json"

        # Create sample config.env
        self.config_content = """
SERVER_IP="192.168.1.100"
ADMIN_USER="testadmin"
SSH_PORT="2245"
SERVER_HOSTNAME="node-alpha"
BOOTSTRAP_USER="root"
BOOTSTRAP_PORT="22"
SWAP_SIZE_GB="2"
"""
        self.config_file.write_text(self.config_content.strip())

    def tearDown(self):
        self.test_dir.cleanup()

    def test_load_base_config(self):
        with patch.object(lamo_mod, "CONFIG_PATH", self.config_file):
            cfg = lamo_mod.load_base_config()
            self.assertEqual(cfg["SERVER_IP"], "192.168.1.100")
            self.assertEqual(cfg["ADMIN_USER"], "testadmin")
            self.assertEqual(cfg["SSH_PORT"], "2245")
            self.assertEqual(cfg["SERVER_HOSTNAME"], "node-alpha")

    def test_load_base_config_without_server_ip_when_nodes_exist(self):
        empty_cfg_file = self.test_path / "empty_config.env"
        empty_cfg_file.write_text("ADMIN_USER=test\n")

        nodes_data = {
            "default": "my-node",
            "nodes": {
                "my-node": {"host": "1.2.3.4", "port": 2245, "user": "admin"}
            }
        }
        self.nodes_file.write_text(json.dumps(nodes_data))

        with patch.object(lamo_mod, "CONFIG_PATH", empty_cfg_file), \
             patch.object(lamo_mod, "NODES_CONFIG_PATH", self.nodes_file):
            cfg = lamo_mod.load_base_config()
            self.assertEqual(cfg["ADMIN_USER"], "test")

    def test_nodes_registry_auto_initialization(self):
        with patch.object(lamo_mod, "CONFIG_PATH", self.config_file), \
             patch.object(lamo_mod, "NODES_CONFIG_PATH", self.nodes_file):
            cfg = lamo_mod.load_base_config()
            reg = lamo_mod.get_nodes_registry(cfg)

            self.assertTrue(self.nodes_file.exists())
            self.assertEqual(reg["default"], "node-alpha")
            self.assertIn("node-alpha", reg["nodes"])
            node_data = reg["nodes"]["node-alpha"]
            self.assertEqual(node_data["host"], "192.168.1.100")
            self.assertEqual(node_data["port"], 2245)
            self.assertEqual(node_data["user"], "testadmin")

    def test_resolve_active_node_default_and_explicit(self):
        with patch.object(lamo_mod, "CONFIG_PATH", self.config_file), \
             patch.object(lamo_mod, "NODES_CONFIG_PATH", self.nodes_file):
            base_cfg = lamo_mod.load_base_config()
            reg = lamo_mod.get_nodes_registry(base_cfg)

            # Add second node
            reg["nodes"]["node-beta"] = {
                "name": "node-beta",
                "host": "192.168.1.101",
                "port": 2245,
                "user": "betaadmin",
                "hostname": "node-beta",
            }
            lamo_mod.save_nodes_registry(reg)

            # Resolve default
            resolved_default, _ = lamo_mod.resolve_active_node(base_cfg, target_node_name=None)
            self.assertEqual(resolved_default["NODE_NAME"], "node-alpha")
            self.assertEqual(resolved_default["SERVER_IP"], "192.168.1.100")

            # Resolve explicit node-beta
            resolved_beta, _ = lamo_mod.resolve_active_node(base_cfg, target_node_name="node-beta")
            self.assertEqual(resolved_beta["NODE_NAME"], "node-beta")
            self.assertEqual(resolved_beta["SERVER_IP"], "192.168.1.101")
            self.assertEqual(resolved_beta["ADMIN_USER"], "betaadmin")

    def test_logging_and_retention_defaults_and_node_overrides(self):
        with patch.object(lamo_mod, "CONFIG_PATH", self.config_file), \
             patch.object(lamo_mod, "NODES_CONFIG_PATH", self.nodes_file):
            base_cfg = lamo_mod.load_base_config()
            # Check baseline defaults
            self.assertEqual(base_cfg.get("USER_AUDIT_RETENTION_DAYS"), "7")
            self.assertEqual(base_cfg.get("JOURNALD_MAX_USE_MB"), "150")
            self.assertEqual(base_cfg.get("DOCKER_LOG_MAX_SIZE"), "10m")
            self.assertEqual(base_cfg.get("DOCKER_LOG_MAX_FILES"), "3")

            reg = lamo_mod.get_nodes_registry(base_cfg)
            reg["nodes"]["node-custom-logs"] = {
                "name": "node-custom-logs",
                "host": "192.168.1.102",
                "port": 2245,
                "user": "customadmin",
                "audit_retention_days": 14,
                "journald_max_use_mb": 250,
                "docker_log_max_size": "20m",
                "docker_log_max_files": "5",
                "container_runtime": "podman",
            }
            lamo_mod.save_nodes_registry(reg)

            resolved, _ = lamo_mod.resolve_active_node(base_cfg, "node-custom-logs")
            self.assertEqual(resolved["USER_AUDIT_RETENTION_DAYS"], "14")
            self.assertEqual(resolved["JOURNALD_MAX_USE_MB"], "250")
            self.assertEqual(resolved["DOCKER_LOG_MAX_SIZE"], "20m")
            self.assertEqual(resolved["DOCKER_LOG_MAX_FILES"], "5")
            self.assertEqual(resolved["CONTAINER_RUNTIME"], "podman")

            node_env = lamo_mod.get_node_env(resolved)
            self.assertEqual(node_env["USER_AUDIT_RETENTION_DAYS"], "14")
            self.assertEqual(node_env["JOURNALD_MAX_USE_MB"], "250")
            self.assertEqual(node_env["DOCKER_LOG_MAX_SIZE"], "20m")
            self.assertEqual(node_env["DOCKER_LOG_MAX_FILES"], "5")
            self.assertEqual(node_env["CONTAINER_RUNTIME"], "podman")

    def test_node_add_and_remove(self):
        with patch.object(lamo_mod, "CONFIG_PATH", self.config_file), \
             patch.object(lamo_mod, "NODES_CONFIG_PATH", self.nodes_file):
            base_cfg = lamo_mod.load_base_config()
            reg = lamo_mod.get_nodes_registry(base_cfg)

            # Add node
            args_add = MagicMock(
                node_action="add",
                target_name="worker-1",
                host="10.0.0.5",
                port=2245,
                user="deploy",
                notes="Worker 1",
                audit_retention_days=10,
                journald_max_use_mb=200,
                docker_log_max_size="15m",
                docker_log_max_files="4",
                runtime="podman",
            )
            lamo_mod.cmd_node_action(base_cfg, args_add)

            # Verify it's in registry
            reg_updated = lamo_mod.get_nodes_registry(base_cfg)
            self.assertIn("worker-1", reg_updated["nodes"])
            self.assertEqual(reg_updated["nodes"]["worker-1"]["host"], "10.0.0.5")
            self.assertEqual(reg_updated["nodes"]["worker-1"]["audit_retention_days"], 10)
            self.assertEqual(reg_updated["nodes"]["worker-1"]["journald_max_use_mb"], 200)
            self.assertEqual(reg_updated["nodes"]["worker-1"]["docker_log_max_size"], "15m")
            self.assertEqual(reg_updated["nodes"]["worker-1"]["docker_log_max_files"], "4")
            self.assertEqual(reg_updated["nodes"]["worker-1"]["container_runtime"], "podman")

            # Switch default node
            args_use = MagicMock(node_action="use", target_name="worker-1")
            lamo_mod.cmd_node_action(base_cfg, args_use)
            reg_switched = lamo_mod.get_nodes_registry(base_cfg)
            self.assertEqual(reg_switched["default"], "worker-1")

            # Remove original node
            args_rm = MagicMock(node_action="remove", target_name="node-alpha")
            lamo_mod.cmd_node_action(base_cfg, args_rm)
            reg_after_rm = lamo_mod.get_nodes_registry(base_cfg)
            self.assertNotIn("node-alpha", reg_after_rm["nodes"])
            self.assertEqual(reg_after_rm["default"], "worker-1")

    def test_ssh_mux_opts_per_node(self):
        cfg_alpha = {"NODE_NAME": "alpha", "SERVER_IP": "10.0.0.1", "SSH_PORT": "2245"}
        cfg_beta = {"NODE_NAME": "beta", "SERVER_IP": "10.0.0.2", "SSH_PORT": "2245"}

        opts_alpha = lamo_mod.get_ssh_mux_opts(cfg_alpha)
        opts_beta = lamo_mod.get_ssh_mux_opts(cfg_beta)

        # Ensure different socket paths for different nodes
        path_alpha = [opts_alpha[i+1] for i, opt in enumerate(opts_alpha) if opt == "-o" and "ControlPath=" in opts_alpha[i+1]][0]
        path_beta = [opts_beta[i+1] for i, opt in enumerate(opts_beta) if opt == "-o" and "ControlPath=" in opts_beta[i+1]][0]

        self.assertIn("alpha.sock", path_alpha)
        self.assertIn("beta.sock", path_beta)
        self.assertNotEqual(path_alpha, path_beta)


class TestLamoArgparse(unittest.TestCase):
    def test_parser_subcommands(self):
        # Verify parser creation and routing without exit
        with patch("sys.argv", ["lamo", "node", "list"]):
            base_cfg = {
                "SERVER_IP": "127.0.0.1",
                "ADMIN_USER": "test",
                "SSH_PORT": "22",
                "SERVER_HOSTNAME": "test",
            }
            with patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
                 patch.object(lamo_mod, "cmd_list_nodes") as mock_list:
                lamo_mod.main()
                mock_list.assert_called_once_with(base_cfg)

    def test_parser_node_flag(self):
        with patch("sys.argv", ["lamo", "-n", "server2", "app", "list"]):
            base_cfg = {
                "SERVER_IP": "127.0.0.1",
                "ADMIN_USER": "test",
                "SSH_PORT": "22",
                "SERVER_HOSTNAME": "test",
            }
            resolved_cfg = dict(base_cfg)
            resolved_cfg["NODE_NAME"] = "server2"
            resolved_cfg["SERVER_IP"] = "10.0.0.2"

            with patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
                 patch.object(lamo_mod, "resolve_active_node", return_value=(resolved_cfg, {})) as mock_res, \
                 patch.object(lamo_mod, "run_ssh") as mock_ssh:
                lamo_mod.main()
                mock_res.assert_called_once_with(base_cfg, "server2")
                mock_ssh.assert_called_once_with(resolved_cfg, "sudo -u bover bover list")

    def test_backup_routing(self):
        base_cfg = {
            "SERVER_IP": "127.0.0.1",
            "ADMIN_USER": "test",
            "SSH_PORT": "22",
            "SERVER_HOSTNAME": "test",
        }
        test_cases = [
            (["lamo", "app", "backup", "config"], "sudo -u bover bover backup config", True),
            (["lamo", "app", "backup", "all"], "sudo -u bover bover backup all", False),
            (["lamo", "app", "backup", "myapp"], "sudo -u bover bover backup run myapp", False),
            (["lamo", "app", "backup", "run", "myapp"], "sudo -u bover bover backup run myapp", False),
            (["lamo", "app", "backup", "myapp", "app2"], "sudo -u bover bover backup run myapp app2", False),
            (["lamo", "app", "backup", "run", "myapp", "app2"], "sudo -u bover bover backup run myapp app2", False),
            (["lamo", "app", "backup", "list"], "sudo -u bover bover backup list", False),
            (["lamo", "app", "backup", "list", "myapp"], "sudo -u bover bover backup list myapp", False),
            (["lamo", "app", "backup", "verify", "myapp"], "sudo -u bover bover backup verify myapp", False),
            (["lamo", "app", "backup", "verify", "myapp", "--key", "myapp/test.tar.gz"], "sudo -u bover bover backup verify myapp --key myapp/test.tar.gz", False),
        ]
        for argv, expected_cmd, is_interactive in test_cases:
            with patch("sys.argv", argv), \
                 patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
                 patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
                 patch.object(lamo_mod, "run_ssh") as mock_ssh:
                lamo_mod.main()
                if is_interactive:
                    mock_ssh.assert_called_once_with(base_cfg, expected_cmd, interactive=True)
                else:
                    mock_ssh.assert_called_once_with(base_cfg, expected_cmd)

    def test_node_namespace_routing(self):
        base_cfg = {
            "SERVER_IP": "127.0.0.1",
            "ADMIN_USER": "test",
            "SSH_PORT": "22",
            "SERVER_HOSTNAME": "test",
        }
        with patch("sys.argv", ["lamo", "node", "list"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "cmd_list_nodes") as mock_list:
                lamo_mod.main()
                mock_list.assert_called_once_with(base_cfg)

    def test_app_namespace_routing(self):
        base_cfg = {
            "SERVER_IP": "127.0.0.1",
            "ADMIN_USER": "test",
            "SSH_PORT": "22",
            "SERVER_HOSTNAME": "test",
        }
        # 1. app list routes to cmd_list_apps_multi
        with patch("sys.argv", ["lamo", "app", "list"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "cmd_list_apps_multi") as mock_list_apps:
            lamo_mod.main()
            mock_list_apps.assert_called_once_with(base_cfg, None)

        # 2. app status <name> routes to bover status <name>
        with patch("sys.argv", ["lamo", "app", "status", "testapp"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
             patch.object(lamo_mod, "run_ssh") as mock_ssh:
            lamo_mod.main()
            mock_ssh.assert_called_once_with(base_cfg, "sudo -u bover bover status testapp")

        # 3. app stats <name> routes to bover stats <name>
        with patch("sys.argv", ["lamo", "app", "stats", "testapp"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
             patch.object(lamo_mod, "run_ssh") as mock_ssh:
            lamo_mod.main()
            mock_ssh.assert_called_once_with(base_cfg, "sudo -u bover bover stats testapp")

        # 4. app config <name> routes to bover config <name>
        with patch("sys.argv", ["lamo", "app", "config", "testapp"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
             patch.object(lamo_mod, "run_ssh") as mock_ssh:
            lamo_mod.main()
            mock_ssh.assert_called_once_with(base_cfg, "sudo -u bover bover config testapp")

    def test_node_stats_and_apps_routing(self):
        base_cfg = {
            "SERVER_IP": "127.0.0.1",
            "ADMIN_USER": "test",
            "SSH_PORT": "22",
            "SERVER_HOSTNAME": "test",
        }
        # 1. node stats routes to bover node-stats
        with patch("sys.argv", ["lamo", "node", "stats"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
             patch.object(lamo_mod, "run_ssh") as mock_ssh:
            try:
                lamo_mod.main()
            except SystemExit:
                pass
            mock_ssh.assert_called_once_with(base_cfg, "sudo -u bover bover node-stats")

        # 2. node apps <target> routes to cmd_list_apps_multi
        with patch("sys.argv", ["lamo", "node", "apps", "worker-1"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "cmd_list_apps_multi") as mock_list_apps:
            lamo_mod.main()
            mock_list_apps.assert_called_once_with(base_cfg, target_node_name="worker-1")

        # 3. node caddy status routes to bover caddy status
        with patch("sys.argv", ["lamo", "node", "caddy", "status"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
             patch.object(lamo_mod, "run_ssh") as mock_ssh:
            lamo_mod.main()
            mock_ssh.assert_called_once_with(base_cfg, "sudo -u bover bover caddy status")

        # 4. node caddy stats routes to bover caddy stats
        with patch("sys.argv", ["lamo", "node", "caddy", "stats"]), \
             patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
             patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
             patch.object(lamo_mod, "run_ssh") as mock_ssh:
            lamo_mod.main()
            mock_ssh.assert_called_once_with(base_cfg, "sudo -u bover bover caddy stats")

    def test_top_level_setup_and_first_vps_onboarding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            cfg_path = tmp_path / "config.env"
            nodes_path = tmp_path / "nodes.json"
            with patch.object(lamo_mod, "CONFIG_PATH", cfg_path), \
                 patch.object(lamo_mod, "NODES_CONFIG_PATH", nodes_path), \
                 patch("builtins.input", side_effect=["203.0.113.10", "first-node", "admin", "2245", "root", "22", "docker"]), \
                 patch.object(lamo_mod, "cmd_setup") as mock_setup, \
                 patch("sys.argv", ["lamo", "setup"]):
                lamo_mod.main()
                mock_setup.assert_called_once()
                called_cfg = mock_setup.call_args[0][0]
                self.assertEqual(called_cfg["SERVER_IP"], "203.0.113.10")
                self.assertEqual(called_cfg["NODE_NAME"], "first-node")
                self.assertEqual(called_cfg["ADMIN_USER"], "admin")
                self.assertEqual(called_cfg["SSH_PORT"], "2245")
                self.assertTrue(nodes_path.exists())
                self.assertTrue(cfg_path.exists())

    def test_cron_routing(self):
        base_cfg = {
            "SERVER_IP": "127.0.0.1",
            "ADMIN_USER": "test",
            "SSH_PORT": "22",
            "SERVER_HOSTNAME": "test",
        }
        test_cases = [
            (["lamo", "app", "cron", "list"], "sudo -u bover bover cron list"),
            (["lamo", "app", "cron", "list", "myapp"], "sudo -u bover bover cron list myapp"),
            (["lamo", "app", "crons", "list", "myapp"], "sudo -u bover bover cron list myapp"),
            (
                ["lamo", "app", "cron", "add", "myapp", "nightly-job", "0 3 * * *", "python manage.py cleanup", "--mode", "run", "--timeout", "600"],
                "sudo -u bover bover cron add myapp nightly-job '0 3 * * *' 'python manage.py cleanup' --mode run --timeout 600 --notify on_failure",
            ),
            (["lamo", "app", "cron", "run", "myapp", "nightly-job"], "sudo -u bover bover cron run myapp nightly-job"),
            (["lamo", "app", "cron", "history", "myapp", "--job", "nightly-job", "-n", "10"], "sudo -u bover bover cron history myapp --job nightly-job -n 10"),
            (["lamo", "app", "cron", "show", "12"], "sudo -u bover bover cron show 12"),
            (["lamo", "app", "cron", "disable", "myapp", "nightly-job"], "sudo -u bover bover cron disable myapp nightly-job"),
            (["lamo", "app", "cron", "enable", "myapp", "nightly-job"], "sudo -u bover bover cron enable myapp nightly-job"),
            (["lamo", "app", "cron", "remove", "myapp", "nightly-job"], "sudo -u bover bover cron remove myapp nightly-job"),
        ]
        for argv, expected_cmd in test_cases:
            with patch("sys.argv", argv), \
                 patch.object(lamo_mod, "load_base_config", return_value=base_cfg), \
                 patch.object(lamo_mod, "resolve_active_node", return_value=(base_cfg, {})), \
                 patch.object(lamo_mod, "run_ssh") as mock_ssh:
                lamo_mod.main()
                mock_ssh.assert_called_once_with(base_cfg, expected_cmd)


if __name__ == "__main__":
    unittest.main()
