import os
import pytest
import azure_cloud_defender
from pprint import PrettyPrinter
import json
from azure.mgmt.security.v2019_01_01_preview.models import SecuritySubAssessment
from azure.mgmt.security.v2021_06_01.models import SecurityAssessmentResponse

import azure

PP = PrettyPrinter(indent=4, width=300, compact=False).pprint


@pytest.fixture
def ew():
    class EventWriter:
        def __init__(self):
            self.count = 0

        def write_event(self, event):
            pass
            # self.count += 1
            # print(self.count)
            # if 'subAssessmentsLink' in event['data']:
            #     j = json.loads(event["data"])
            #     PP(j)

    return EventWriter()


@pytest.fixture
def acd(ew):
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
    acd.event_writer = ew
    return acd


@pytest.fixture
def sub_ids(acd):
    subscriptions = acd.get_subscriptions()
    return acd.subscription_ids(subscriptions)


@pytest.fixture
def sar():
    sar = SecurityAssessmentResponse()
    sar.additional_data = {}
    sar.additional_data.update(
        {
            "subAssessmentsLink": "/subscriptions/63ed7111-101c-4849-9f33-03ef672ed20d/providers/Microsoft.Security/assessments/fde1c0c9-0fd2-4ecc-87b5-98956cbc1095/subAssessments"
        }
    )
    return sar


@pytest.mark.live
def test_get_azure_credentials(acd):
    creds = acd.get_azure_creds()
    assert creds


@pytest.mark.live
def test_get_subscriptions(acd):
    subscriptions = list(acd.get_subscriptions())
    assert subscriptions


def test_extract_assessment_resource_scope(sar):
    scope = sar.sub_assessment_resource_scope()
    assert scope == "/subscriptions/63ed7111-101c-4849-9f33-03ef672ed20d"


@pytest.mark.live
def test_get_assessments(acd, sub_ids):
    for sub_id in sub_ids:
        assessments = list(acd.get_assessments(sub_id))
        for assessment in assessments:
            assert assessment.type == "Microsoft.Security/assessments"


@pytest.mark.live
def test_get_assessments_metadata(acd, sub_ids):
    for sub_id in sub_ids:
        assessments_metadata = list(acd.get_assessment_metadata(sub_id))
        for assessment_metadata in assessments_metadata:
            assert assessment_metadata.type == "Microsoft.Security/assessmentMetadata"


# Base Class
def test_can_instantiate(acd):
    acd = azure_cloud_defender.ModInputAzureCloudDefender()
    assert acd


def test_get_scheme(acd):
    scheme = acd.get_scheme()
    assert scheme


@pytest.mark.skip(reason="Azure API response doesn't match documentation")
def test_get_contacts(acd, sub_ids):
    for sub_id in sub_ids:
        contacts = acd.get_contacts(sub_id)
        assert contacts


# @pytest.mark.live
# def test_get_sub_assessments(acd, sub_ids):
#     for sub_id in sub_ids:
#         sub_assessments = acd.get_sub_assessments(sub_id)
#         assert sub_assessments


@pytest.mark.live
def test_get_assessment_metadata(acd, sub_ids):
    for sub_id in sub_ids:
        assessment_metadata = acd.get_assessment_metadata(sub_id)
        assert assessment_metadata


@pytest.mark.live
def test_collect_events(acd, ew):
    events = acd.collect_events(ew)
    assert events


@pytest.mark.live
def test_get_sub_assessment_fail(acd, sar, sub_ids):
    assessments = list(acd.get_assessments(sub_ids[0]))
    events = acd.get_sub_assessments(assessments[0])
    assert 0 == len(events)


@pytest.mark.live
def test_get_events_threaded(acd, ew):
    events = acd.get_events_threaded()
    assert events
