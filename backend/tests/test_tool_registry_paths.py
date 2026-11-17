from app.config import settings
from app.tools import registry


def test_resolve_tool_path_maps_nikto_directory_to_script(monkeypatch, workspace_tmp_dir):
    nikto_dir = workspace_tmp_dir / "nikto"
    script_path = nikto_dir / "program" / "nikto.pl"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("#!/usr/bin/perl\n", encoding="utf-8")

    monkeypatch.setattr(settings, "NIKTO_PATH", str(nikto_dir), raising=False)
    monkeypatch.setattr(registry, "APP_BIN_DIR", workspace_tmp_dir / "bin", raising=False)
    monkeypatch.setattr(registry, "VENV_SCRIPTS_DIR", workspace_tmp_dir / "venv_scripts", raising=False)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: None)

    resolved = registry.resolve_tool_path("nikto")

    assert resolved == str(script_path)


def test_resolve_tool_path_skips_non_file_candidates(monkeypatch, workspace_tmp_dir):
    fake_nmap_dir = workspace_tmp_dir / "nmap"
    fake_nmap_dir.mkdir()

    monkeypatch.setattr(settings, "NMAP_PATH", str(fake_nmap_dir), raising=False)
    monkeypatch.setattr(registry, "APP_BIN_DIR", workspace_tmp_dir / "bin", raising=False)
    monkeypatch.setattr(registry, "VENV_SCRIPTS_DIR", workspace_tmp_dir / "venv_scripts", raising=False)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: None)

    resolved = registry.resolve_tool_path("nmap")

    assert resolved is None


def test_get_tool_plan_includes_nikto_git_source(monkeypatch, workspace_tmp_dir):
    nikto_dir = workspace_tmp_dir / "nikto"
    script_path = nikto_dir / "program" / "nikto.pl"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("#!/usr/bin/perl\n", encoding="utf-8")

    monkeypatch.setattr(settings, "NIKTO_PATH", str(nikto_dir), raising=False)
    monkeypatch.setattr(settings, "NIKTO_GIT_SOURCE", str(workspace_tmp_dir / "nikto_backup_1"), raising=False)
    monkeypatch.setattr(registry, "APP_BIN_DIR", workspace_tmp_dir / "bin", raising=False)
    monkeypatch.setattr(registry, "VENV_SCRIPTS_DIR", workspace_tmp_dir / "venv_scripts", raising=False)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: None)

    plan = registry.get_tool_plan("nikto", "deep", "https://example.com")

    assert plan is not None
    assert plan["config"]["nikto_git_source"] == str(workspace_tmp_dir / "nikto_backup_1")


def test_resolve_tool_path_maps_wapiti_directory_to_script(monkeypatch, workspace_tmp_dir):
    wapiti_dir = workspace_tmp_dir / "wapiti-main"
    script_path = wapiti_dir / "bin" / "wapiti"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    monkeypatch.setattr(settings, "WAPITI_PATH", str(wapiti_dir), raising=False)
    monkeypatch.setattr(registry, "APP_BIN_DIR", workspace_tmp_dir / "bin", raising=False)
    monkeypatch.setattr(registry, "VENV_SCRIPTS_DIR", workspace_tmp_dir / "venv_scripts", raising=False)
    monkeypatch.setattr(registry, "EXTERNAL_TOOL_ROOTS", (), raising=False)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: None)

    resolved = registry.resolve_tool_path("wapiti")

    assert resolved == str(script_path)


def test_resolve_tool_path_uses_external_niktowap_for_wapiti(monkeypatch, workspace_tmp_dir):
    external_root = workspace_tmp_dir / "niktowap"
    script_path = external_root / "wapiti-master" / "bin" / "wapiti"
    script_path.parent.mkdir(parents=True)
    script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    monkeypatch.setattr(settings, "WAPITI_PATH", "", raising=False)
    monkeypatch.setattr(registry, "APP_BIN_DIR", workspace_tmp_dir / "bin", raising=False)
    monkeypatch.setattr(registry, "VENV_SCRIPTS_DIR", workspace_tmp_dir / "venv_scripts", raising=False)
    monkeypatch.setattr(registry, "EXTERNAL_TOOL_ROOTS", (external_root,), raising=False)
    monkeypatch.setattr(registry.shutil, "which", lambda _name: None)

    resolved = registry.resolve_tool_path("wapiti")

    assert resolved == str(script_path)
