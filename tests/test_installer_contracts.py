"""Regression tests for the installer and rendered systemd contract."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "ZeroXSHDW_autosnort-ubuntu.sh"
UNIT = ROOT / "snortd.service"


class InstallerContractTests(unittest.TestCase):
    def test_configuration_is_data_not_shell_code(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("function load_config()", source)
        self.assertNotIn('source "$conf_file"', source)
        self.assertNotIn("eval ", source)

    def test_downloads_keep_tls_verification_enabled(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertNotIn("--no-check-certificate", source)
        self.assertGreaterEqual(source.count("--https-only"), 4)

    def test_reboot_is_opt_in(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertNotIn("init 6", source)
        self.assertIn("if (( REBOOT == 1 )); then", source)
        self.assertIn("--reboot", source)

    def test_systemd_template_is_foreground_and_parameterized(self) -> None:
        unit = UNIT.read_text(encoding="utf-8")

        for placeholder in (
            "@SNORT_BASEDIR@",
            "@SNORT_IFACE_1@",
            "@SNORT_IFACE_2@",
        ):
            self.assertIn(placeholder, unit)
        self.assertIn("Type=simple", unit)
        self.assertNotIn(" -D ", unit)

    def test_check_mode_validates_without_mutating_or_executing_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            shutil.copy2(INSTALLER, directory / INSTALLER.name)
            shutil.copy2(UNIT, directory / UNIT.name)

            target = directory / "not-created"
            (directory / "full_autosnort.conf").write_text(
                f"snort_basedir={target}\n"
                "snort_iface_1=eth1\n"
                "snort_iface_2=eth2\n"
                "o_code=0123456789abcdef0123456789abcdef01234567\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(directory / INSTALLER.name), "--check"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists())

            marker = directory / "should-not-run"
            (directory / "full_autosnort.conf").write_text(
                "snort_basedir=/opt/snort\n"
                "snort_iface_1=eth1\n"
                "snort_iface_2=eth2\n"
                "o_code=0123456789abcdef0123456789abcdef01234567\n"
                f"touch {marker}\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(directory / INSTALLER.name), "--check"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
