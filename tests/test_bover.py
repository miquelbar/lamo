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
                    self.assertIn("NoNewPrivileges=true", unit_content)
                    self.assertIn("ProtectSystem=strict", unit_content)


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
                self.assertEqual(meta_json["backup_version"], 1)

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


if __name__ == "__main__":
    unittest.main()
