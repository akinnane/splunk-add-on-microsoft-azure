import os
import pytest
import azure_cloud_defender
from pprint import PrettyPrinter
import json
from azure.mgmt.security.v2019_01_01_preview.models import SecuritySubAssessment

import azure

PP = PrettyPrinter(indent=4, width=300, compact=False, sort_dicts=True).pprint


@pytest.fixture
def ew():
    class EventWriter:
        def __init__(self):
            pass

        def write_event(self, event):
            pprint(event)
            # pass

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


@pytest.mark.live
def test_get_subscriptions(acd):
    subscriptions = list(acd.get_subscriptions())
    assert subscriptions


@pytest.mark.live
def test_get_tasks(acd, sub_ids):
    for sub_id in sub_ids:
        tasks = list(acd.get_tasks(sub_id))
        print(list(task.as_dict() for task in tasks))
        assert tasks


def test_extract_assessment_resource_scope(acd):
    link = "/subscriptions/63ed7111-101c-4849-9f33-03ef672ed20d/providers/Microsoft.Security/assessments/fde1c0c9-0fd2-4ecc-87b5-98956cbc1095/subAssessments"
    scope = acd.assessment_resource_scope(link)
    assert scope == "/subscriptions/63ed7111-101c-4849-9f33-03ef672ed20d"
from azure.mgmt.security.v2019_01_01_preview.models import SecuritySubAssessment

@pytest.mark.live
def test_get_assessments(acd, sub_ids):
    ssa = SecuritySubAssessment()
    for sub_id in sub_ids:
        assessments = list(acd.get_assessments(sub_id))
        for assessment in assessments:
            assert assessment.type == "Microsoft.Security/assessments"

            assessment = acd.smash_has_assessments_sub_assessment(assessment)
            print(assessment.sub_assessments)
            assessment.sub_assessments = [ssa]
            # if not assessment.sub_assessments:
            #     continue

            # assessment._attribute_map.update({"sub_assessments": {'key': 'sub_assessments', 'type': '{object}'}})
            # assessment.__dict__.update({'sub_assessments': None})
            # assessment._attribute_map.update({"task": {'key': 'task', 'type': 'SecurityTask'}})
            # tasks = acd.get_tasks(sub_id)
            # assessment.__dict__.update({'task': next(tasks) })
            pprint(ssa.as_dict())

            pprint(assessment._attribute_map)
            print("as_dict()")
            pprint(assessment.as_dict())
            pprint(assessment.resource_details.serialize(keep_readonly=True))
            print("__dict__")
            pprint(assessment.__dict__)
            print("dir")
            print(dir(assessment))
            pprint(assessment.metadata)
            pprint(assessment.serialize(keep_readonly=True))
            assert False


@pytest.mark.live
def test_get_assessments_metadata(acd, sub_ids):
    for sub_id in sub_ids:
        assessments_metadata = list(acd.get_assessments_metadata(sub_id))
        for assessment_metadata in assessments_metadata:
            assert assessment_metadata.type == "Microsoft.Security/assessmentMetadata"


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
def test_collect_events(acd, ew):
    events = acd.collect_events(ew)
    assert events
    print(events)
    assert False


@pytest.mark.live
def test_get_sub_assessment_fail(acd):
    events = acd.get_sub_assessment("/fofofofoffofofofofo")
    # pprint(events)
    assert 1 == len(events)


@pytest.mark.live
def test_smash_events_threaded(acd):
    events = acd.smash_events_threaded()
    assert events


@pytest.mark.live
def test_smash_events_serial(acd):
    events = acd.smash_events()
    assert events
