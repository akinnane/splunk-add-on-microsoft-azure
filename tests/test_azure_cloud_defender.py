import os
import pytest
import azure_cloud_defender


@pytest.fixture
def ew():
    class EventWriter:
        def __init__(self):
            pass

        def write_event(self, event):
            print(event)

    return EventWriter()


@pytest.fixture
def acd():
    acd = azure_cloud_defender.ModInputAzureCloudDefender()
    azure_app_account = {
        "azure_app_account": {
            "username": os.environ["azure_client_id"],
            "password": os.environ["azure_client_secret"],
        },
        "tenant_id": os.environ["azure_tenant_id"],
        "environment": "global",
        "collect_security_center_alerts": True,
        "collect_security_center_tasks": True,
    }

    acd.input_stanzas["someapp"] = azure_app_account

    # Fake out proxy settings
    class Empty:
        pass

    acd.setup_util = Empty()
    acd.setup_util.get_proxy_settings = lambda: None
    acd.get_check_point = lambda a: None
    acd.save_check_point = lambda a, b: None
    acd.new_event = lambda data, source, index, sourcetype: {
        "data": data,
        "source": source,
        "index": index,
        "sourcetype": sourcetype,
    }
    return acd


def test_can_instantiate(acd):
    acd = azure_cloud_defender.ModInputAzureCloudDefender()
    assert acd


def test_acd_collect_events(acd, ew):
    acd.collect_events(ew)
