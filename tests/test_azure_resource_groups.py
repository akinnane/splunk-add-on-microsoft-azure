import os
import pytest
import azure_resource_group


@pytest.fixture
def ew():
    class EventWriter:
        def __init__(self):
            pass

        def write_event(self, event):
            print(event)

    return EventWriter()


@pytest.fixture
def arg():
    arg = azure_resource_group.ModInputazure_resource_group()
    azure_app_account = {
        "azure_app_account": {
            "username": os.environ["azure_client_id"],
            "password": os.environ["azure_client_secret"],
        },
        "tenant_id": os.environ["azure_tenant_id"],
        "environment": "global",
        "subscription_id": os.environ.get("subscription_id", "default_id"),
    }

    arg.input_stanzas["someapp"] = azure_app_account

    # Fake out proxy settings
    class Empty:
        pass

    arg.setup_util = Empty()
    arg.setup_util.get_proxy_settings = lambda: None
    arg.get_check_point = lambda a: None
    arg.save_check_point = lambda a, b: None
    arg.new_event = lambda data, source, index, sourcetype: {
        "data": data,
        "source": source,
        "index": index,
        "sourcetype": sourcetype,
    }
    return arg


def test_can_instantiate(arg):
    assert arg


@pytest.mark.live
def test_arg_collect_events(arg, ew):
    events = arg.get_resource_groups("TODO")
    print(events)
    assert events
    assert len(events) == 3


@pytest.mark.live
def test_arg_collect_events(arg, ew):
    events = arg.collect_events(ew)
    print(events)
    assert events
    assert len(events) == 8
