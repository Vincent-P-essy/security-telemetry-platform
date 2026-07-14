from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_telemetry_platform.api import create_app
from security_telemetry_platform.cli import main
from security_telemetry_platform.loader import load_default_scenarios, load_scenarios


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_loader_default_and_file(tmp_path: Path) -> None:
    assert len(load_default_scenarios()) == 4
    path = tmp_path / "s.yaml"
    path.write_text(
        "scenarios:\n"
        "  - name: tiny\n"
        "    description: t\n"
        "    service_chain: [a]\n"
        "    anomaly_metric: m\n"
        "    baseline_value: 1\n"
        "    drift_metric: m\n"
        "    drift_baseline: [1]\n"
        "    drift_current: [1]\n",
        encoding="utf-8",
    )
    assert load_scenarios(path)[0].name == "tiny"


def test_loader_rejects_bad_documents(tmp_path: Path) -> None:
    non_mapping = tmp_path / "b.yaml"
    non_mapping.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_scenarios(non_mapping)

    no_list = tmp_path / "c.yaml"
    no_list.write_text("scenarios: 5\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scenarios"):
        load_scenarios(no_list)


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"


def test_scenarios_and_correlate(client: TestClient) -> None:
    assert len(client.get("/scenarios").json()["scenarios"]) == 4
    summary = client.get("/correlate").json()
    assert summary["incidents"] == 2
    one = client.get("/correlate/credential-stuffing").json()
    assert one["counts"]["total_alerts"] == 3
    assert client.get("/correlate/nope").status_code == 404


def test_exporter_endpoints(client: TestClient) -> None:
    prom = client.get("/export/credential-stuffing/prometheus")
    assert prom.status_code == 200
    assert "# TYPE" in prom.text
    assert client.get("/export/credential-stuffing/jaeger").json()["data"][0]["spans"]
    assert client.get("/export/credential-stuffing/loki").json()["streams"]


def test_dashboard(client: TestClient) -> None:
    assert client.get("/").status_code == 200


def _capture(capsys: pytest.CaptureFixture[str]) -> object:
    return json.loads(capsys.readouterr().out)


def test_cli_correlate_all(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["correlate", "all"]) == 0
    assert _capture(capsys)["scenarios"] == 4


def test_cli_correlate_named(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["correlate", "data-exfiltration"]) == 0
    assert _capture(capsys)["counts"]["security_alerts"] == 1


def test_cli_correlate_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["correlate", "nope"]) == 2


def test_cli_export(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["export", "credential-stuffing", "--format", "prometheus"]) == 0
    assert "# TYPE" in capsys.readouterr().out


def test_cli_export_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["export", "nope", "--format", "loki"]) == 2


def test_cli_report_and_benchmark(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", "--out", str(tmp_path)]) == 0
    assert Path(_capture(capsys)["json"]).exists()
    assert main(["benchmark", "--iterations", "2", "--out", str(tmp_path)]) == 0
    assert _capture(capsys)["deterministic"] is True
