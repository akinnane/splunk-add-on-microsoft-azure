import os

import azure_defender_alerts
import pytest


@pytest.fixture
def ada(ew):
    ada = azure_defender_alerts.ModInputazure_defender_alerts()
    azure_app_account = {
        "azure_app_account": {
            "username": os.environ.get("azure_client_id"),
            "password": os.environ.get("azure_client_secret"),
        },
        "tenant_id": os.environ.get("azure_tenant_id"),
        "environment": "global",
        "subscription_id": os.environ.get("subscription_id", "default_id"),
    }

    ada.input_stanzas["someapp"] = azure_app_account

    # Fake out proxy settings
    class Empty:
        pass

    ada.setup_util = Empty()
    ada.setup_util.get_proxy_settings = lambda: None
    ada.get_check_point = lambda a: None
    ada.save_check_point = lambda a, b: None
    ada.new_event = lambda data, source, index, sourcetype: {
        "data": data,
        "source": source,
        "index": index,
        "sourcetype": sourcetype,
    }
    return ada


def test_can_instantiate(ada):
    assert ada


def test_get_scheme(ada):
    scheme = ada.get_scheme()
    assert scheme


@pytest.mark.live
def test_ada_collect_events(ada, ew):
    events = ada.collect_events(ew)
    assert events
    for event in events:
        assert event
        assert "SSPHP_RUN" in event
