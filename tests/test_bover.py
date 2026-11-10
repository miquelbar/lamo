#!/usr/bin/env python3
"""
Unit tests for Bover (Es Bover) Server Cattle Daemon & Runtime Worker.
Tests Caddyfile generation, byte conversions, environment isolation,
and SQLite metrics initialization.
"""

import sys
import os
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Import bover module
import importlib.util
spec = importlib.util.spec_from_file_location("bover", str(BASE_DIR / "scripts" / "bover-cli.py"))
bover_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bover_mod)


class TestBoverCaddyGeneration(unittest.TestCase):
    def test_generate_caddy_rule_structure(self):
        rule = bover_mod.generate_caddy_rule(
            name="demoapp",
            domain="demo.example.com",
            port=8080,
            target_host="demoapp-green"
        )

        # 1. Check domain block
        self.assertIn("demo.example.com {", rule)

        # 2. Check TLS & Security headers imports
        self.assertIn("import tls-security", rule)
        self.assertIn("import security-headers", rule)

        # 3. Check compression & JSON logging
        self.assertIn("encode zstd gzip", rule)
        self.assertIn("output file /var/log/caddy/demoapp-access.log", rule)
        self.assertIn("format json", rule)

        # 4. Check Reverse Proxy upstream & port
        self.assertIn("reverse_proxy demoapp-green:8080 {", rule)

        # 5. Check Server footprint removal headers
        self.assertIn("header_down -Server", rule)
        self.assertIn("header_down -X-Powered-By", rule)

    def test_generate_caddy_rule_with_redirects(self):
        rule = bover_mod.generate_caddy_rule(
            name="myapp",
            domain="www.example.com",
            port=8080,
            target_host="myapp-blue",
            redirects=["example.com", "app.example.com"]
        )

        self.assertIn("example.com {\n    redir https://www.example.com{uri} permanent", rule)
        self.assertIn("app.example.com {\n    redir https://www.example.com{uri} permanent", rule)
        self.assertIn("www.example.com {", rule)
        self.assertIn("reverse_proxy myapp-blue:8080", rule)

    def test_resolve_app_volumes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            app_dir = Path(tmp_dir) / "testapp"
            app_dir.mkdir(parents=True)
            (app_dir / "data").mkdir()

            # 1. Default convention: {app_dir}/data:/data
            vols = bover_mod.resolve_app_volumes({}, app_dir)
            self.assertEqual(vols, [f"{app_dir.resolve()}/data:/data"])

            # 2. Custom data_dir
            ext_dir = Path(tmp_dir) / "external_disk"
            vols = bover_mod.resolve_app_volumes({"data_dir": str(ext_dir)}, app_dir)
            self.assertEqual(vols, [f"{ext_dir.resolve()}:/data"])
            self.assertTrue(ext_dir.exists())

            # 3. Explicit volumes list
            vols = bover_mod.resolve_app_volumes({"volumes": ["/mnt/disk/data:/data", "/mnt/disk/media:/media"]}, app_dir)
            self.assertEqual(vols, ["/mnt/disk/data:/data", "/mnt/disk/media:/media"])


class TestBoverByteParsingAndFormatting(unittest.TestCase):
    def test_parse_bytes(self):
        self.assertEqual(bover_mod.parse_bytes("1024B"), 1024)
        self.assertEqual(bover_mod.parse_bytes("1KB"), 1000)
        self.assertEqual(bover_mod.parse_bytes("1KiB"), 1024)
        self.assertEqual(bover_mod.parse_bytes("2.5MB"), int(2.5 * 1000 * 1000))
        self.assertEqual(bover_mod.parse_bytes("4GiB"), 4 * 1024 * 1024 * 1024)
        self.assertEqual(bover_mod.parse_bytes("invalid"), 0)

    def test_format_bytes(self):
        self.assertEqual(bover_mod.format_bytes(1024 * 500), "500.0 KB")
        self.assertEqual(bover_mod.format_bytes(1024 * 1024), "1.0 MB")
        self.assertEqual(bover_mod.format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB")

    def test_format_table(self):
        headers = ["APP", "DOMAIN", "STATUS"]
        rows = [["my-app", "app.example.com", "running"]]
        hdr, sep, r_lines = bover_mod.format_table(headers, rows, max_width=80)
        self.assertIn("APP", hdr)
        self.assertIn("my-app", r_lines[0])
        self.assertEqual(len(hdr), len(sep))
        self.assertLessEqual(len(hdr), 80)


class TestBoverStateAndConfig(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.apps_dir = Path(self.test_dir.name) / "apps"
        self.apps_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.apps_dir / "stats.db"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_app_config_and_state_io(self):
        app_name = "testservice"
        app_path = self.apps_dir / app_name
        app_path.mkdir(parents=True, exist_ok=True)

        config_data = {
            "name": app_name,
            "domain": "test.local",
            "port": 3000,
            "auto_deploy": True,
            "keep_versions": 5,
        }
        (app_path / "app.json").write_text(bover_mod.json.dumps(config_data))

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir):
            loaded_cfg = bover_mod.load_app_config(app_name)
            self.assertIsNotNone(loaded_cfg)
            self.assertEqual(loaded_cfg["port"], 3000)
            self.assertEqual(loaded_cfg["keep_versions"], 5)

            # Test state saving and loading
            sample_state = {
                "active_slot": "blue",
                "active_commit": "abc1234",
                "last_deploy": "2026-11-04T07:00:00Z"
            }
            bover_mod.save_app_state(app_name, sample_state)
            loaded_state = bover_mod.load_app_state(app_name)
            self.assertEqual(loaded_state["active_slot"], "blue")
            self.assertEqual(loaded_state["active_commit"], "abc1234")

    def test_add_app_computational_resource_limits(self):
        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "deploy_app"):
            # 1. Default resources
            bover_mod.add_app(
                name="defaultres",
                domain="default.local",
                port=8080
            )
            cfg_default = bover_mod.load_app_config("defaultres")
            self.assertEqual(cfg_default["cpu"], 0.5)
            self.assertEqual(cfg_default["memory"], "512m")

            # 2. Custom resources
            bover_mod.add_app(
                name="customres",
                domain="custom.local",
                port=8080,
                cpu=1.5,
                memory="1g"
            )
            cfg_custom = bover_mod.load_app_config("customres")
            self.assertEqual(cfg_custom["cpu"], 1.5)
            self.assertEqual(cfg_custom["memory"], "1g")

    def test_database_init(self):
        with patch.object(bover_mod, "DB_PATH", self.db_path):
            bover_mod.init_db()
            self.assertTrue(self.db_path.exists())

            # Verify tables were created
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()

            self.assertIn("deployments", tables)
            self.assertIn("metrics", tables)
            self.assertIn("app_disk_metrics", tables)
            self.assertIn("app_visits", tables)
            self.assertIn("cron_executions", tables)
            self.assertIn("cron_state", tables)

    def test_systemd_units_least_privilege(self):
        with patch("pathlib.Path.write_text") as mock_write, \
             patch.object(bover_mod, "run_cmd"):
            bover_mod.install_systemd_units()

            written_units = [call[0][0] for call in mock_write.call_args_list if isinstance(call[0][0], str)]
            self.assertTrue(len(written_units) > 0)
            for unit_content in written_units:
                if "[Service]" in unit_content:
                    self.assertIn("User=bover", unit_content)
                    self.assertIn("Group=bover", unit_content)
                    self.assertIn("ProtectSystem=strict", unit_content)
                    # Services that invoke scoped sudo helper (bover-backup, bover-autodeploy)
                    # must NOT have NoNewPrivileges=true so kernel allows sudo execution
                    if "bover backup all" in unit_content or "bover autodeploy" in unit_content:
                        self.assertNotIn("NoNewPrivileges=true", unit_content)
                    else:
                        self.assertIn("NoNewPrivileges=true", unit_content)


class TestBoverVaultAndIsolation(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.vault_dir = Path(self.test_dir.name) / ".vault"
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.apps_dir = Path(self.test_dir.name) / "apps"
        self.apps_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_vault_encrypt_decrypt_roundtrip(self):
        with patch.object(bover_mod, "VAULT_DIR", self.vault_dir):
            secret_text = "secret_telegram_token_123456:ABC-DEF_xyz"
            encrypted = bover_mod.vault_encrypt(secret_text)
            self.assertNotEqual(secret_text, encrypted)
            self.assertTrue(len(encrypted) > 10)

            decrypted = bover_mod.vault_decrypt(encrypted)
            self.assertEqual(secret_text, decrypted)

    def test_vault_save_and_load_secret(self):
        with patch.object(bover_mod, "VAULT_DIR", self.vault_dir):
            payload = {"bot_token": "987654321:XYZ", "chat_id": "11223344"}
            bover_mod.save_vault_secret("telegram", payload)

            enc_file = self.vault_dir / "telegram.enc"
            self.assertTrue(enc_file.exists())
            self.assertNotIn("987654321:XYZ", enc_file.read_text())

            loaded = bover_mod.load_vault_secret("telegram")
            self.assertEqual(loaded, payload)

    def test_validate_app_name(self):
        # Valid names
        self.assertEqual(bover_mod.validate_app_name("myapp"), "myapp")
        self.assertEqual(bover_mod.validate_app_name("web-service_1"), "web-service_1")
        self.assertEqual(bover_mod.validate_app_name("api.v2"), "api.v2")

        # Invalid names
        with self.assertRaises(ValueError):
            bover_mod.validate_app_name("")
        with self.assertRaises(ValueError):
            bover_mod.validate_app_name("../evil")
        with self.assertRaises(ValueError):
            bover_mod.validate_app_name("app;rm -rf")
        with self.assertRaises(ValueError):
            bover_mod.validate_app_name("app/sub")
        with self.assertRaises(ValueError):
            bover_mod.validate_app_name("-invalid_start")

    def test_get_or_create_app_user_allocation(self):
        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "run_cmd") as mock_cmd:
            username, uid = bover_mod.get_or_create_app_user("my-cool-app")
            self.assertEqual(username, "app_my_cool_app")
            self.assertGreaterEqual(uid, 2001)
            self.assertLessEqual(uid, 2999)
            self.assertTrue(mock_cmd.called)


    def test_send_telegram_custom_alert(self):
        with patch.object(bover_mod, "load_vault_secret", return_value={"bot_token": "token123", "chat_id": "chat456", "enabled": True}), \
             patch("urllib.request.urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_url.return_value.__enter__.return_value = mock_resp

            ok = bover_mod.send_telegram("Security alert message")
            self.assertTrue(ok)
            self.assertTrue(mock_url.called)

    def test_run_app_backup_packages_config_env_and_data(self):
        import io
        import tarfile
        import sqlite3

        app_name = "testapp"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        data_dir = app_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        # Create dummy database
        db_path = data_dir / "app.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE users (id INT, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'Alice')")
        conn.commit()
        conn.close()

        # Create dummy file
        (data_dir / "file.txt").write_text("hello data")

        # Create app.json
        cfg_data = {
            "name": app_name,
            "domain": "test.example.com",
            "port": 8080,
            "volumes": [f"{data_dir}:/data"]
        }
        (app_dir / "app.json").write_text(json.dumps(cfg_data))

        # Create .env
        (app_dir / ".env").write_text("SECRET_KEY=supersecret\nDB_PASS=xyz\n")

        # Create shared .env
        shared_dir = self.apps_dir / "shared"
        shared_dir.mkdir(parents=True, exist_ok=True)
        (shared_dir / ".env").write_text("SHARED_VAR=common\n")

        # Mock S3 upload
        captured_data = []

        def mock_s3_put(endpoint_url, bucket, key, data, access_key, secret_key):
            captured_data.append(data)
            return True, None

        s3_creds = {
            "bucket": "backups-bucket",
            "access_key": "dummy_key",
            "secret_key": "dummy_secret",
            "account_id": "dummy_acc",
        }

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "load_s3_config", return_value=s3_creds), \
             patch.object(bover_mod, "s3_sigv4_put", side_effect=mock_s3_put), \
             patch.object(bover_mod, "notify_backup_result"):
            success, r2_key, file_size, duration = bover_mod.run_app_backup(app_name)
            self.assertTrue(success)
            self.assertIn("testapp/backup_testapp_", r2_key)
            self.assertGreater(file_size, 0)
            self.assertGreaterEqual(duration, 0.0)
            self.assertEqual(len(captured_data), 1)

            # Inspect tar contents
            with tarfile.open(fileobj=io.BytesIO(captured_data[0]), mode="r:gz") as tar:
                names = tar.getnames()
                self.assertIn("app.json", names)
                self.assertIn(".env", names)
                self.assertIn("shared.env", names)
                self.assertIn("backup-metadata.json", names)
                self.assertIn("data/app.db", names)
                self.assertIn("data/file.txt", names)

                # Verify contents
                env_content = tar.extractfile(".env").read().decode()
                self.assertIn("SECRET_KEY=supersecret", env_content)

                app_json_content = tar.extractfile("app.json").read().decode()
                self.assertIn("test.example.com", app_json_content)

                meta_content = tar.extractfile("backup-metadata.json").read().decode()
                meta_json = json.loads(meta_content)
                self.assertEqual(meta_json["app"], "testapp")
                self.assertGreaterEqual(meta_json["backup_version"], 1)
                self.assertTrue(len(meta_json.get("databases", [])) > 0)
                self.assertEqual(meta_json["databases"][0]["filename"], "app.db")
                self.assertEqual(meta_json["databases"][0]["integrity_check"], "ok")

    def test_caddy_status_and_stats(self):
        mock_probe = {
            "alive": True,
            "container_state": "Up 5 hours",
            "ip": "172.20.0.2",
            "responding": True,
            "http_code": 200,
            "latency_ms": 1.5,
            "error": None,
        }
        mock_disk = (1048576, 524288, 1024, 523264)
        mock_domains = ["example.com", "app.example.com"]

        test_db = Path(self.test_dir.name) / "test_caddy.db"
        with patch.object(bover_mod, "probe_caddy_health", return_value=mock_probe), \
             patch.object(bover_mod, "measure_caddy_disk", return_value=mock_disk), \
             patch.object(bover_mod, "get_caddy_routed_domains", return_value=mock_domains), \
             patch.object(bover_mod, "run_cmd", return_value="0.1%|34.2MiB / 512MiB"), \
             patch.object(bover_mod, "DB_PATH", test_db), \
             patch("builtins.print") as mock_print:
            bover_mod.show_caddy_status()
            printed = " ".join([call[0][0] for call in mock_print.call_args_list if call[0] and isinstance(call[0][0], str)])
            self.assertIn("Central Gateway & Reverse Proxy", printed)
            self.assertIn("caddy", printed)
            self.assertIn("example.com", printed)

            # Test direct show_caddy_stats
            bover_mod.show_caddy_stats()

        with patch.object(bover_mod, "show_caddy_status") as mock_show_caddy:
            bover_mod.show_app_status("caddy")
            mock_show_caddy.assert_called_once()

        with patch.object(bover_mod, "show_caddy_stats") as mock_show_caddy_stats:
            bover_mod.show_stats("caddy")
            mock_show_caddy_stats.assert_called_once()

    def test_notify_backup_summary_consolidated(self):
        # 1. Single app should delegate to notify_backup_result
        single_res = [{
            "app": "app1",
            "success": True,
            "destination_key": "r2://bucket/app1/backup.tar.gz",
            "file_size_bytes": 1048576,
            "error": None,
            "duration": 2.5,
        }]
        with patch.object(bover_mod, "notify_backup_result") as mock_single, \
             patch.object(bover_mod, "send_telegram") as mock_tg:
            bover_mod.notify_backup_summary(single_res)
            mock_single.assert_called_once_with(
                app_name="app1",
                success=True,
                destination_key="r2://bucket/app1/backup.tar.gz",
                file_size_bytes=1048576,
                error=None,
                duration=2.5,
            )
            mock_tg.assert_not_called()

        # 2. Multiple apps should consolidate into a single Telegram message
        multi_res = [
            {
                "app": "app1",
                "success": True,
                "destination_key": "r2://bucket/app1/backup.tar.gz",
                "file_size_bytes": 1048576,
                "error": None,
                "duration": 2.0,
            },
            {
                "app": "app2",
                "success": False,
                "destination_key": None,
                "file_size_bytes": 0,
                "error": "Connection reset by peer",
                "duration": 1.5,
            },
        ]
        with patch.object(bover_mod, "run_cmd", return_value="node1"), \
             patch.object(bover_mod, "send_telegram") as mock_tg:
            bover_mod.notify_backup_summary(multi_res)
            mock_tg.assert_called_once()
            msg = mock_tg.call_args[0][0]
            self.assertIn("ES BOVER · COPIAS DE SEGURIDAD", msg)
            self.assertIn("node1", msg)
            self.assertIn("1/2 completadas", msg)
            self.assertIn("app1", msg)
            self.assertIn("app2", msg)
            self.assertIn("Connection reset by peer", msg)

    def test_run_backups_batch_sends_only_one_notification(self):
        s3_creds = {
            "bucket": "backups-bucket",
            "access_key": "key",
            "secret_key": "secret",
            "account_id": "acc",
        }
        with patch.object(bover_mod, "load_s3_config", return_value=s3_creds), \
             patch.object(bover_mod, "run_app_backup") as mock_run_backup, \
             patch.object(bover_mod, "notify_backup_summary") as mock_summary:
            mock_run_backup.side_effect = [
                (True, "app1/backup_app1.tar.gz", 2048, 1.2),
                (True, "app2/backup_app2.tar.gz", 4096, 2.3),
            ]
            results = bover_mod.run_backups_batch(["app1", "app2"])
            self.assertEqual(len(results), 2)
            self.assertEqual(mock_run_backup.call_count, 2)
            mock_run_backup.assert_any_call("app1", notify=False)
            mock_run_backup.assert_any_call("app2", notify=False)
            mock_summary.assert_called_once_with(results)

    def test_deploy_journal_checkpoint_and_resume(self):
        app_dir = self.apps_dir / "resumetest"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "app.json").write_text(json.dumps({
            "name": "resumetest",
            "domain": "resume.example.com",
            "port": 3000,
        }))
        (app_dir / "Dockerfile").write_text("FROM alpine\n")

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "CONF_DIR", self.apps_dir / "gateway" / "conf.d"), \
             patch.object(bover_mod, "DRAIN_SECONDS", 0), \
             patch.object(bover_mod, "get_or_create_app_user", return_value=("app-resumetest", 2001)), \
             patch.object(bover_mod, "git_sync") as mock_git, \
             patch.object(bover_mod, "run_healthcheck", return_value=True) as mock_hc, \
             patch.object(bover_mod, "reload_caddy"), \
             patch.object(bover_mod, "enable_app_systemd"), \
             patch.object(bover_mod, "record_deployment_finish", return_value=3.5), \
             patch.object(bover_mod, "notify_deploy_success"), \
             patch.object(bover_mod, "prune_app_versions"), \
             patch.object(bover_mod, "refresh_docker_cache"), \
             patch.object(bover_mod, "run_cmd", return_value="") as mock_cmd:
            # Save a checkpoint journal simulating a reboot right before 'healthcheck'
            bover_mod.save_deploy_journal("resumetest", {
                "app": "resumetest",
                "phase": "healthcheck",
                "no_pull": False,
                "triggered_by": "cli",
                "current_slot": "blue",
                "target_slot": "green",
                "target_container": "resumetest-green",
                "old_container": "resumetest-blue",
                "commit": "abc1234",
                "commit_msg": "feat: test resume",
                "deploy_id": 42,
                "started_at": 1000,
            })
            loaded = bover_mod.load_deploy_journal("resumetest")
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["phase"], "healthcheck")

            ok = bover_mod.deploy_app("resumetest", resume=True)
            self.assertTrue(ok)
            # git_sync and docker build must be skipped since checkpoint was already at 'healthcheck'
            mock_git.assert_not_called()
            executed_cmds = [c[0][0] for c in mock_cmd.call_args_list]
            self.assertFalse(any("docker build" in cmd for cmd in executed_cmds))
            mock_hc.assert_called_once()
            # Journal must be cleared upon completion and active_slot updated to 'green'
            self.assertIsNone(bover_mod.load_deploy_journal("resumetest"))
            state = bover_mod.load_app_state("resumetest")
            self.assertEqual(state["active_slot"], "green")
            self.assertEqual(state["commit"], "abc1234")

    def test_sqlite_database_integrity_inspection(self):
        # 1. Test healthy database
        db_file = self.apps_dir / "healthy.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL);")
        conn.execute("INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob');")
        conn.execute("INSERT INTO orders VALUES (10, 1, 99.5);")
        conn.commit()
        conn.close()

        report = bover_mod.inspect_sqlite_database(db_file)
        self.assertTrue(report["valid"])
        self.assertEqual(report["integrity_check"], "ok")
        self.assertEqual(report["total_tables"], 2)
        self.assertEqual(report["total_records"], 3)
        self.assertEqual(report["tables"]["users"], 2)
        self.assertEqual(report["tables"]["orders"], 1)

        # 2. Test corrupted database
        corrupt_file = self.apps_dir / "corrupted.db"
        corrupt_file.write_bytes(b"NOT A SQLITE DATABASE CORRUPTED DATA" * 10)
        corrupt_report = bover_mod.inspect_sqlite_database(corrupt_file)
        self.assertFalse(corrupt_report["valid"])
        self.assertNotEqual(corrupt_report["integrity_check"], "ok")

        # 3. Test non-existent database
        missing_report = bover_mod.inspect_sqlite_database(self.apps_dir / "missing.db")
        self.assertFalse(missing_report["valid"])
        self.assertEqual(missing_report["integrity_check"], "empty_or_missing")

    def test_verify_backup_archive_valid_and_invalid(self):
        import tarfile

        app_name = "sampleapp"
        staging = self.apps_dir / "staging_test"
        staging.mkdir(parents=True, exist_ok=True)
        data_staging = staging / "data"
        data_staging.mkdir(parents=True, exist_ok=True)

        # Write valid db
        conn = sqlite3.connect(str(data_staging / "app.db"))
        conn.execute("CREATE TABLE items (id INT, title TEXT);")
        conn.execute("INSERT INTO items VALUES (1, 'Widget');")
        conn.commit()
        conn.close()

        (staging / "app.json").write_text(json.dumps({"name": app_name, "domain": "sample.com", "port": 8000}))
        (staging / ".env").write_text("API_KEY=12345\n")
        (staging / "backup-metadata.json").write_text(json.dumps({"app": app_name, "backup_version": 2}))

        valid_tar = self.apps_dir / "valid_backup.tar.gz"
        with tarfile.open(valid_tar, "w:gz") as tar:
            for item in staging.iterdir():
                tar.add(item, arcname=item.name)

        ok, res = bover_mod.verify_backup_archive(valid_tar, app_name=app_name)
        self.assertTrue(ok)
        self.assertTrue(res["valid"])
        self.assertEqual(len(res["db_reports"]), 1)
        self.assertEqual(res["db_reports"][0]["filename"], "app.db")
        self.assertEqual(res["db_reports"][0]["integrity_check"], "ok")
        self.assertEqual(res["db_reports"][0]["tables"]["items"], 1)

        # Corrupt archive
        corrupt_tar = self.apps_dir / "corrupted_backup.tar.gz"
        corrupt_tar.write_bytes(b"garbage bytes that cannot decompress with gzip")
        corrupt_ok, corrupt_res = bover_mod.verify_backup_archive(corrupt_tar, app_name=app_name)
        self.assertFalse(corrupt_ok)
        self.assertIn("error", corrupt_res)

    def test_s3_sigv4_get_and_list_mocked(self):
        xml_response = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <Contents>
        <Key>myapp/backup_myapp_2026-11-09_05-00-00.tar.gz</Key>
        <LastModified>2026-11-09T05:00:00.000Z</LastModified>
        <Size>12345</Size>
    </Contents>
</ListBucketResult>"""

        class MockResponse:
            def __init__(self, data, status=200):
                self.data = data
                self.status = status
            def read(self):
                return self.data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        with patch("urllib.request.urlopen", return_value=MockResponse(xml_response)):
            ok, objs = bover_mod.s3_sigv4_list(
                endpoint_url="https://test_acc.r2.cloudflarestorage.com",
                bucket="test-bucket",
                prefix="myapp/",
                access_key="test_access",
                secret_key="test_secret"
            )
            self.assertTrue(ok)
            self.assertEqual(len(objs), 1)
            self.assertEqual(objs[0]["key"], "myapp/backup_myapp_2026-11-09_05-00-00.tar.gz")
            self.assertEqual(objs[0]["size"], 12345)

        with patch("urllib.request.urlopen", return_value=MockResponse(b"GZIP_TAR_MOCK_DATA")):
            ok, data = bover_mod.s3_sigv4_get(
                endpoint_url="https://test_acc.r2.cloudflarestorage.com",
                bucket="test-bucket",
                key="myapp/backup_myapp_2026-11-09_05-00-00.tar.gz",
                access_key="test_access",
                secret_key="test_secret"
            )
            self.assertTrue(ok)
            self.assertEqual(data, b"GZIP_TAR_MOCK_DATA")

    def test_rotate_local_backups_retention_window(self):
        from datetime import datetime, timezone, timedelta
        app_name = "testapp"
        backups_dir = self.apps_dir / "backups" / app_name
        backups_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc)
        f_recent = backups_dir / f"backup_{app_name}_{(now - timedelta(days=1)).strftime('%Y-%m-%d_%H-%M-%S')}.tar.gz"
        f_within = backups_dir / f"backup_{app_name}_{(now - timedelta(days=3)).strftime('%Y-%m-%d_%H-%M-%S')}.tar.gz"
        f_old1 = backups_dir / f"backup_{app_name}_{(now - timedelta(days=10)).strftime('%Y-%m-%d_%H-%M-%S')}.tar.gz"
        f_old2 = backups_dir / f"backup_{app_name}_{(now - timedelta(days=30)).strftime('%Y-%m-%d_%H-%M-%S')}.tar.gz"

        for f in (f_recent, f_within, f_old1, f_old2):
            f.write_bytes(b"dummy backup data")

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir):
            pruned, freed = bover_mod.rotate_local_backups(app_name, keep_days=5)
            self.assertEqual(pruned, 2)
            self.assertGreater(freed, 0)
            self.assertTrue(f_recent.exists())
            self.assertTrue(f_within.exists())
            self.assertFalse(f_old1.exists())
            self.assertFalse(f_old2.exists())

            # Test safety: if all remaining backups are old, newest is still preserved
            pruned2, _ = bover_mod.rotate_local_backups(app_name, keep_days=0)
            self.assertEqual(pruned2, 1)
            self.assertTrue(f_recent.exists())
            self.assertFalse(f_within.exists())


class TestBoverCronScheduler(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.apps_dir = Path(self.test_dir.name) / "apps"
        self.apps_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.apps_dir / "stats.db"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_cron_schedule_validation_and_matching(self):
        from datetime import datetime
        # Valid macros and 5-field expressions
        self.assertEqual(bover_mod.normalize_cron_schedule("@daily"), "0 0 * * *")
        self.assertEqual(bover_mod.normalize_cron_schedule("@every 15m"), "*/15 * * * *")
        self.assertEqual(bover_mod.normalize_cron_schedule("@every 2h"), "0 */2 * * *")
        self.assertEqual(bover_mod.validate_cron_schedule("30 3 * * mon-fri"), "30 3 * * mon-fri")

        # 2026-11-06 is a Friday (weekday=4, cron_dow=5)
        dt_fri_0330 = datetime(2026, 11, 6, 3, 30)
        dt_fri_0331 = datetime(2026, 11, 6, 3, 31)
        dt_sun_0330 = datetime(2026, 11, 8, 3, 30)

        self.assertTrue(bover_mod.cron_matches_dt("30 3 * * mon-fri", dt_fri_0330))
        self.assertFalse(bover_mod.cron_matches_dt("30 3 * * mon-fri", dt_fri_0331))
        self.assertFalse(bover_mod.cron_matches_dt("30 3 * * mon-fri", dt_sun_0330))
        self.assertTrue(bover_mod.cron_matches_dt("30 3 * * sun", dt_sun_0330))
        self.assertTrue(bover_mod.cron_matches_dt("30 3 * * 7", dt_sun_0330))

        # Invalid expressions must raise ValueError
        with self.assertRaises(ValueError):
            bover_mod.validate_cron_schedule("invalid cron")
        with self.assertRaises(ValueError):
            bover_mod.validate_cron_schedule("65 0 * * *")
        with self.assertRaises(ValueError):
            bover_mod.validate_cron_schedule("0 25 * * *")

    def test_cron_crud_and_repo_sync(self):
        app_name = "cronapp"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "cron.example.com",
            "port": 8080,
        }))

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "DB_PATH", self.db_path):
            # Add cron via CLI helper
            bover_mod.cron_add(
                app_name=app_name,
                job_id="cleanup-tokens",
                schedule="0 3 * * *",
                command="python manage.py cleartokens",
                mode="exec",
                timeout=120,
                notify="on_failure",
                description="Clean expired tokens",
            )
            cfg = bover_mod.load_app_config(app_name)
            crons = bover_mod.get_app_crons(cfg)
            self.assertEqual(len(crons), 1)
            self.assertEqual(crons[0]["id"], "cleanup-tokens")
            self.assertEqual(crons[0]["mode"], "exec")
            self.assertTrue(crons[0]["enabled"])

            # Disable & re-enable
            bover_mod.cron_toggle(app_name, "cleanup-tokens", enabled=False)
            self.assertFalse(bover_mod.get_app_crons(bover_mod.load_app_config(app_name))[0]["enabled"])
            bover_mod.cron_toggle(app_name, "cleanup-tokens", enabled=True)
            self.assertTrue(bover_mod.get_app_crons(bover_mod.load_app_config(app_name))[0]["enabled"])

            # Declarative repo sync via crons.json merges with existing CLI crons
            (app_dir / "crons.json").write_text(json.dumps([
                {
                    "id": "generate-report",
                    "schedule": "@hourly",
                    "command": "python manage.py report",
                    "mode": "run",
                }
            ]))
            bover_mod.sync_repo_crons(app_name, app_dir)
            crons_merged = bover_mod.get_app_crons(bover_mod.load_app_config(app_name))
            self.assertEqual(len(crons_merged), 2)
            ids = {c["id"] for c in crons_merged}
            self.assertEqual(ids, {"cleanup-tokens", "generate-report"})

            # Remove cron
            bover_mod.cron_remove(app_name, "cleanup-tokens")
            crons_after = bover_mod.get_app_crons(bover_mod.load_app_config(app_name))
            self.assertEqual(len(crons_after), 1)
            self.assertEqual(crons_after[0]["id"], "generate-report")

    def test_execute_cron_job_exec_and_run_modes_with_audit_log_and_telegram(self):
        app_name = "workerapp"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "data").mkdir(parents=True, exist_ok=True)
        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "worker.example.com",
            "port": 8000,
            "cpu": 0.5,
            "memory": "512m",
        }))

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "DB_PATH", self.db_path), \
             patch.object(bover_mod, "get_or_create_app_user", return_value=("app_workerapp", 2010)), \
             patch.object(bover_mod, "_resolve_active_container_for_cron", return_value="workerapp-blue"), \
             patch.object(bover_mod, "run_cmd", return_value="OK"), \
             patch.object(bover_mod, "send_telegram") as mock_tg:
            bover_mod.save_app_state(app_name, {"active_slot": "blue", "container": "workerapp-blue"})

            # 1. Successful 'exec' mode job (notify='on_failure' -> no Telegram alert)
            mock_proc_ok = MagicMock(returncode=0, stdout="Cleaned 42 rows\n")
            with patch("subprocess.run", return_value=mock_proc_ok) as mock_sub:
                res_ok = bover_mod.execute_cron_job(app_name, {
                    "id": "db-vacuum",
                    "schedule": "0 4 * * *",
                    "command": "python vacuum.py",
                    "mode": "exec",
                    "notify": "on_failure",
                }, triggered_by="manual")

                self.assertEqual(res_ok["status"], "SUCCESS")
                self.assertEqual(res_ok["exit_code"], 0)
                self.assertEqual(res_ok["output"], "Cleaned 42 rows")
                self.assertGreaterEqual(res_ok["duration_sec"], 0.0)
                called_argv = mock_sub.call_args[0][0]
                self.assertEqual(called_argv[:5], ["docker", "exec", "-u", "2010:2010", "workerapp-blue"])
                mock_tg.assert_not_called()

            # 2. Failed 'run' (ephemeral isolated container) mode job -> triggers Telegram alert
            mock_proc_fail = MagicMock(returncode=2, stdout="Fatal error: DB locked\n")
            with patch("subprocess.run", return_value=mock_proc_fail) as mock_sub2:
                res_fail = bover_mod.execute_cron_job(app_name, {
                    "id": "heavy-export",
                    "schedule": "0 5 * * *",
                    "command": "python export.py",
                    "mode": "run",
                    "notify": "on_failure",
                }, triggered_by="schedule")

                self.assertEqual(res_fail["status"], "FAILED")
                self.assertEqual(res_fail["exit_code"], 2)
                called_argv2 = mock_sub2.call_args[0][0]
                self.assertEqual(called_argv2[:3], ["docker", "run", "--rm"])
                self.assertIn("workerapp:blue", called_argv2)
                mock_tg.assert_called_once()
                self.assertIn("FALLO EN CRON", mock_tg.call_args[0][0])
                self.assertIn("heavy-export", mock_tg.call_args[0][0])

            # 3. Verify both executions are persisted in SQLite cron_executions
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM cron_executions WHERE app = ? ORDER BY id ASC", (app_name,)).fetchall()
            conn.close()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["job_id"], "db-vacuum")
            self.assertEqual(rows[0]["status"], "SUCCESS")
            self.assertEqual(rows[1]["job_id"], "heavy-export")
            self.assertEqual(rows[1]["status"], "FAILED")
            self.assertEqual(rows[1]["exit_code"], 2)

    def test_cron_tick_catchup_and_idempotency(self):
        from datetime import datetime
        app_name = "tickapp"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "tick.example.com",
            "port": 8080,
            "crons": [
                {
                    "id": "hourly-sync",
                    "schedule": "0 * * * *",
                    "command": "echo sync",
                    "mode": "exec",
                }
            ]
        }))

        # Timestamp at exactly 10:00:00 local time
        t_1000 = int(datetime(2026, 11, 7, 10, 0, 5).timestamp())
        # Timestamp at 10:03:00 local time (simulating delayed timer after 11:00:00)
        t_1058 = int(datetime(2026, 11, 7, 10, 58, 0).timestamp())
        t_1103 = int(datetime(2026, 11, 7, 11, 3, 12).timestamp())

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "DB_PATH", self.db_path), \
             patch.object(bover_mod, "execute_cron_job", return_value={"run_id": 1, "status": "SUCCESS"}) as mock_exec:
            # 1. Tick at 10:00 runs once
            res1 = bover_mod.cron_tick(now_ts=t_1000)
            self.assertEqual(len(res1), 1)
            self.assertEqual(mock_exec.call_count, 1)

            # 2. Second tick within the same minute (10:00:45) does NOT double-execute
            res_dup = bover_mod.cron_tick(now_ts=t_1000 + 40)
            self.assertEqual(len(res_dup), 0)
            self.assertEqual(mock_exec.call_count, 1)

            # 3. Tick at 10:58 (not matching 0 * * * *) updates last_slot_ts without executing
            res2 = bover_mod.cron_tick(now_ts=t_1058)
            self.assertEqual(len(res2), 0)

            # 4. If server was busy at 11:00, 11:01, 11:02 and next tick happens at 11:03,
            # catch-up detects missed 11:00 slot and executes it with triggered_by='catchup'!
            res3 = bover_mod.cron_tick(now_ts=t_1103)
            self.assertEqual(len(res3), 1)
            self.assertEqual(mock_exec.call_count, 2)
            self.assertEqual(mock_exec.call_args[0][2], "catchup")


class TestBoverPermissionAndIsolationRegression(unittest.TestCase):
    """
    Regression test suite specifically verifying that file permissions,
    systemd privilege boundaries, container group memberships, and SQLite
    WAL/SHM accessibility cannot regress.
    """
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.apps_dir = Path(self.test_dir.name) / "apps"
        self.apps_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.apps_dir / ".state.db"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_systemd_units_sudo_privilege_boundary_regression(self):
        """
        Verify that bover-backup.service and bover-autodeploy.service do NOT contain
        NoNewPrivileges=true, allowing them to invoke the scoped bover-helper via sudo,
        while strictly sandboxed units without sudo DO retain NoNewPrivileges=true.
        """
        calls = []

        def track_write(path_obj, content):
            calls.append((str(path_obj), content))

        with patch("pathlib.Path.write_text", track_write), \
             patch.object(bover_mod, "run_cmd"):
            bover_mod.install_systemd_units()

        units_dict = {path: content for path, content in calls}

        # 1. Backup service: must run 'bover backup all' as bover:bover without NoNewPrivileges
        bk_service = units_dict.get("/etc/systemd/system/bover-backup.service")
        self.assertIsNotNone(bk_service, "bover-backup.service must be generated")
        self.assertIn("ExecStart=/usr/local/bin/bover backup all", bk_service)
        self.assertIn("User=bover", bk_service)
        self.assertIn("Group=bover", bk_service)
        self.assertIn("ProtectSystem=strict", bk_service)
        self.assertNotIn("NoNewPrivileges=true", bk_service,
                         "bover-backup.service must NOT have NoNewPrivileges=true so sudo can run bover-helper")

        # 2. Autodeploy service: must run 'bover autodeploy' without NoNewPrivileges
        ad_service = units_dict.get("/etc/systemd/system/bover-autodeploy.service")
        self.assertIsNotNone(ad_service, "bover-autodeploy.service must be generated")
        self.assertIn("ExecStart=/usr/local/bin/bover autodeploy", ad_service)
        self.assertIn("User=bover", ad_service)
        self.assertIn("Group=bover", ad_service)
        self.assertIn("ProtectSystem=strict", ad_service)
        self.assertNotIn("NoNewPrivileges=true", ad_service,
                         "bover-autodeploy.service must NOT have NoNewPrivileges=true so sudo can run bover-helper")

        # 3. Units that do not need sudo MUST retain NoNewPrivileges=true
        gw_service = units_dict.get("/etc/systemd/system/bover-gateway.service")
        self.assertIsNotNone(gw_service)
        self.assertIn("NoNewPrivileges=true", gw_service)

        cron_service = units_dict.get("/etc/systemd/system/bover-cron.service")
        self.assertIsNotNone(cron_service)
        self.assertIn("NoNewPrivileges=true", cron_service)

    def test_dockerfile_deploy_injects_group_add_bover_regression(self):
        """
        Verify that deploying a Dockerfile-based app injects --group-add {bover_gid}
        into 'docker run', ensuring container user (app_<name>) has group write to bover files.
        """
        app_name = "horifyreg"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        data_dir = app_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "Dockerfile").write_text("FROM alpine\n")
        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "horifyreg.test",
            "port": 8000,
            "type": "dockerfile",
            "volumes": [f"{data_dir}:/app/data"]
        }))

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "DB_PATH", self.db_path), \
             patch.object(bover_mod, "CONF_DIR", self.apps_dir / "gateway" / "conf.d"), \
             patch.object(bover_mod, "DRAIN_SECONDS", 0), \
             patch.object(bover_mod, "get_bover_gid", return_value=987), \
             patch.object(bover_mod, "get_or_create_app_user", return_value=(f"app_{app_name}", 2194)), \
             patch.object(bover_mod, "git_sync"), \
             patch.object(bover_mod, "run_healthcheck", return_value=True), \
             patch.object(bover_mod, "reload_caddy"), \
             patch.object(bover_mod, "enable_app_systemd"), \
             patch.object(bover_mod, "record_deployment_finish", return_value=1.0), \
             patch.object(bover_mod, "notify_deploy_success"), \
             patch.object(bover_mod, "prune_app_versions"), \
             patch.object(bover_mod, "refresh_docker_cache"), \
             patch.object(bover_mod, "reconcile_app_permissions") as mock_reconcile, \
             patch.object(bover_mod, "run_cmd", return_value="") as mock_cmd:

            ok = bover_mod.deploy_app(app_name, no_pull=True)
            self.assertTrue(ok)

            # Find the 'docker run' command
            executed_cmds = [c[0][0] for c in mock_cmd.call_args_list if isinstance(c[0][0], str)]
            docker_runs = [cmd for cmd in executed_cmds if "docker run" in cmd]
            self.assertTrue(len(docker_runs) > 0, "docker run must have been executed")
            run_cmd_str = docker_runs[0]

            # Assert essential security and permission parameters:
            self.assertIn("--group-add 987", run_cmd_str,
                          "docker run must include '--group-add {bover_gid}' so container can access bover group files")
            self.assertIn("--user 2194:2194", run_cmd_str,
                          "docker run must enforce dedicated app user UID:GID")
            self.assertIn("--security-opt no-new-privileges:true", run_cmd_str)

            # Assert permissions were reconciled on completion
            mock_reconcile.assert_called_with(app_name)

    def test_docker_compose_deploy_injects_group_add_bover_regression(self):
        """
        Verify that deploying a Docker Compose app generates an override containing
        group_add: - "{bover_gid}".
        """
        app_name = "composereg"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "docker-compose.yml").write_text("""
services:
  web:
    image: nginx:alpine
""")
        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "compose.test",
            "port": 80
        }))

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "DB_PATH", self.db_path), \
             patch.object(bover_mod, "CONF_DIR", self.apps_dir / "gateway" / "conf.d"), \
             patch.object(bover_mod, "DRAIN_SECONDS", 0), \
             patch.object(bover_mod, "get_bover_gid", return_value=987), \
             patch.object(bover_mod, "get_or_create_app_user", return_value=(f"app_{app_name}", 2050)), \
             patch.object(bover_mod, "git_sync"), \
             patch.object(bover_mod, "run_healthcheck", return_value=True), \
             patch.object(bover_mod, "reload_caddy"), \
             patch.object(bover_mod, "enable_app_systemd"), \
             patch.object(bover_mod, "record_deployment_finish", return_value=1.0), \
             patch.object(bover_mod, "notify_deploy_success"), \
             patch.object(bover_mod, "prune_app_versions"), \
             patch.object(bover_mod, "refresh_docker_cache"), \
             patch.object(bover_mod, "reconcile_app_permissions"), \
             patch.object(bover_mod, "run_cmd", return_value=""):

            ok = bover_mod.deploy_app(app_name, no_pull=True)
            self.assertTrue(ok)

            override_file = app_dir / ".lamo-override-blue.yml"
            self.assertTrue(override_file.exists())
            content = override_file.read_text()
            self.assertIn("group_add:", content)
            self.assertIn('"987"', content, "docker-compose override must inject group_add with bover_gid")
            self.assertIn('user: "2050:2050"', content)

    def test_reconcile_app_permissions_regression(self):
        """
        Verify reconcile_app_permissions calls bover-helper chown-app with sudo -n
        when running as non-root, handles success and failure cleanly.
        """
        with patch.object(bover_mod, "APPS_DIR", Path("/opt/apps")), \
             patch("pathlib.Path.exists", return_value=True), \
             patch.object(bover_mod, "run_cmd", return_value="OK: Ownership refreshed on '/opt/apps/mytest'.") as mock_cmd:
            ok = bover_mod.reconcile_app_permissions("mytest")
            self.assertTrue(ok)
            called_cmd = mock_cmd.call_args[0][0]
            self.assertIn("/usr/local/bin/bover-helper chown-app mytest", called_cmd)

        # Failure case: returns False without raising
        with patch.object(bover_mod, "APPS_DIR", Path("/opt/apps")), \
             patch("pathlib.Path.exists", return_value=True), \
             patch.object(bover_mod, "run_cmd", return_value="ERROR: sudo failed"):
            ok_fail = bover_mod.reconcile_app_permissions("mytest")
            self.assertFalse(ok_fail)

    def test_bover_helper_script_permissions_contract_regression(self):
        """
        Verify that bover-helper.sh strictly implements SetGID (2770) on data dirs,
        mode 660 on files, mode 660 on .bover* / lock / state / json files,
        and adds app users to group bover.
        """
        helper_path = BASE_DIR / "scripts" / "bover-helper.sh"
        self.assertTrue(helper_path.exists())
        content = helper_path.read_text()

        # SetGID on data directory
        self.assertIn('chmod 2770 "${APP_DIR}/data"', content,
                      "bover-helper must set SetGID (2770) on data directory")
        self.assertIn('find "${APP_DIR}/data" -type d -exec chmod 2770', content,
                      "bover-helper must set 2770 on subdirectories")
        self.assertIn('find "${APP_DIR}/data" -type f -exec chmod 660', content,
                      "bover-helper must set 660 on data files")

        # Permissions on deployment lock, state and app.json
        self.assertIn('chmod 660 "${f}"', content)
        self.assertIn('.*lock*', content)
        self.assertIn('.*state*', content)
        self.assertIn('.bover*', content)

        # App user added to bover group
        self.assertIn('-G bover "${APP_USER}"', content)
        self.assertIn('usermod -a -G bover "${APP_USER}"', content)

    def test_backup_wal_reconciles_permissions_in_all_phases_regression(self):
        """
        Verify that run_app_backup executes reconcile_app_permissions:
        1. Before snapshot
        2. Immediately after database snapshot
        3. In the finally: block (even on error)
        """
        app_name = "waltest"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        data_dir = app_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        # Create simulated WAL database and companions
        db_file = data_dir / "worktime.db"
        conn = sqlite3.connect(str(db_file))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE records (id INT, note TEXT);")
        conn.execute("INSERT INTO records VALUES (1, 'active shift');")
        conn.commit()
        conn.close()

        (data_dir / "worktime.db-wal").write_bytes(b"wal data")
        (data_dir / "worktime.db-shm").write_bytes(b"shm data")

        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "wal.test",
            "port": 8000,
            "volumes": [f"{data_dir}:/data"]
        }))

        s3_creds = {
            "bucket": "test-bucket",
            "access_key": "k",
            "secret_key": "s",
            "account_id": "acc"
        }

        reconcile_calls = []

        def track_reconcile(name):
            reconcile_calls.append(name)
            return True

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "load_s3_config", return_value=s3_creds), \
             patch.object(bover_mod, "s3_sigv4_put", return_value=(True, None)), \
             patch.object(bover_mod, "reconcile_app_permissions", side_effect=track_reconcile):

            ok, _, _, _ = bover_mod.run_app_backup(app_name, notify=False)
            self.assertTrue(ok)
            # Must be called at least 3 times (initial prep, post-sqlite backup, and finally block)
            self.assertGreaterEqual(len(reconcile_calls), 3)

        # Test failure scenario: reconcile must STILL run in finally: block if upload fails
        fail_reconcile_calls = []
        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "load_s3_config", return_value=s3_creds), \
             patch.object(bover_mod, "s3_sigv4_put", side_effect=RuntimeError("S3 connection dropped")), \
             patch.object(bover_mod, "reconcile_app_permissions", side_effect=lambda n: fail_reconcile_calls.append(n)):

            with self.assertRaises(RuntimeError):
                bover_mod.run_app_backup(app_name, notify=False)

            self.assertGreaterEqual(len(fail_reconcile_calls), 2,
                                    "reconcile_app_permissions must execute in finally: even on unexpected failure")

    def test_cron_job_ephemeral_run_injects_group_add_regression(self):
        """
        Verify that execute_cron_job in 'run' mode injects --group-add {bover_gid}.
        """
        app_name = "cronapp"
        app_dir = self.apps_dir / app_name
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "app.json").write_text(json.dumps({
            "name": app_name,
            "domain": "cron.test",
            "port": 8000
        }))

        job = {
            "id": "nightly-cleanup",
            "command": "python manage.py purge",
            "schedule": "0 2 * * *",
            "mode": "run"
        }

        with patch.object(bover_mod, "APPS_DIR", self.apps_dir), \
             patch.object(bover_mod, "DB_PATH", self.db_path), \
             patch.object(bover_mod, "get_bover_gid", return_value=987), \
             patch.object(bover_mod, "get_or_create_app_user", return_value=("app_cronapp", 2099)), \
             patch.object(bover_mod, "run_cmd", return_value="OK"), \
             patch("subprocess.run") as mock_run:

            import subprocess
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="done")

            res = bover_mod.execute_cron_job(app_name, job)
            self.assertEqual(res["status"], "SUCCESS")

            called_args = mock_run.call_args[0][0]
            self.assertIn("--group-add", called_args)
            idx = called_args.index("--group-add")
            self.assertEqual(called_args[idx + 1], "987")


if __name__ == "__main__":
    unittest.main()
