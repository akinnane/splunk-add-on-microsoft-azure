import os
import pytest
import azure_cloud_defender
from pprint import pprint
import json


@pytest.fixture
def ew():
    class EventWriter:
        def __init__(self):
            pass

        def write_event(self, event):
            # pprint(event)
            pass

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
        "security_task_sourcetype": "azure:securitycenter:task",
        "collect_security_assessments": True,
        "security_assessment_sourcetype": "azure:security:assessment",
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


@pytest.fixture
def sub_ids(acd):
    subscriptions = acd.get_subscriptions()
    return acd.subscription_ids(subscriptions)


# Base Class
def test_can_instantiate(acd):
    acd = azure_cloud_defender.ModInputAzureCloudDefender()
    assert acd


def test_get_scheme(acd):
    scheme = acd.get_scheme()
    assert scheme


# Assessments


def test_assessment_metadata(acd):
    md = acd.assessments_metadata("sub_id123")
    expected = {
        "sourcetype": "azure:security:assessment",
        "source": "azure_cloud_defender:sub_id123",
        "index": None,
    }

    assert md == expected


def test_assessment_url(acd):
    subid = "subid123"
    url = acd.assessments_url(subid)
    expected = f"https://management.azure.com/subscriptions/{subid}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
    assert expected == url


@pytest.mark.live
def test_get_assessments(acd, sub_ids):
    for sub_id in sub_ids:
        assessments = acd.get_assessments(sub_id)
        assert assessments


# Contacts


@pytest.mark.skip(reason="Azure API response doesn't match documentation")
def test_get_contacts(acd, sub_ids):
    for sub_id in sub_ids:
        contacts = acd.get_contacts(sub_id)
        assert contacts


# Secure Score
@pytest.mark.live
def test_get_secure_score(acd, sub_ids):
    for sub_id in sub_ids:
        secure_score = acd.get_secure_score(sub_id)
        assert secure_score


# Assessments Metadata
def test_sub_assessment_metadata(acd):
    md = acd.sub_assessments_metadata("sub_id123")
    expected = {
        "sourcetype": "azure:security:sub_assessments",
        "source": "azure_cloud_defender:sub_id123",
        "index": None,
    }

    assert md == expected


# Sub assessments
def test_sub_assessment_url(acd):
    subid = "subid123"
    url = acd.sub_assessments_url(subid)
    expected = f"https://management.azure.com/subscriptions/{subid}/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview"
    assert expected == url


@pytest.mark.live
def test_get_sub_assessments(acd, sub_ids):
    for sub_id in sub_ids:
        sub_assessments = acd.get_sub_assessments(sub_id)
        assert sub_assessments


# Assessment metadata
def test_assessment_metadata_metadata(acd):
    md = acd.assessment_metadata_metadata("sub_id123")
    expected = {
        "sourcetype": "azure:security:assessment_metadata",
        "source": "azure_cloud_defender:sub_id123",
        "index": None,
    }

    assert md == expected


def test_assessment__metadata_url(acd):
    subid = "subid123"
    url = acd.assessment_metadata_url(subid)
    expected = f"https://management.azure.com/subscriptions/{subid}/providers/Microsoft.Security/assessmentMetadata?api-version=2020-01-01"
    assert expected == url


@pytest.mark.live
def test_get_assessment_metadata(acd, sub_ids):
    for sub_id in sub_ids:
        assessment_metadata = acd.get_assessment_metadata(sub_id)
        assert assessment_metadata


@pytest.mark.live
def test_process_events(acd, ew):
    events = acd.collect_events(ew)
    # pprint(events)
    assert False


@pytest.mark.live
def test_get_sub_assessment_fail(acd):
    events = acd.get_sub_assessment("/fofofofoffofofofofo")
    # pprint(events)
    assert 1 == len(events)
