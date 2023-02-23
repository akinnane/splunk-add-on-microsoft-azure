from pprint import PrettyPrinter

import pytest

PP = PrettyPrinter(indent=4, width=300, compact=False).pprint


@pytest.mark.live
def test_get_azure_credentials(az):
    creds = az.get_azure_credentials()
    assert creds


@pytest.mark.live
def test_get_subscriptions(az):
    subscriptions = list(az.get_subscriptions())
    assert subscriptions


@pytest.mark.live
def test_get_assessments(az, sub_ids):
    for sub_id in sub_ids:
        assessments = list(az.get_assessments(sub_id))
        for assessment in assessments:
            assert assessment.type == "Microsoft.Security/assessments"


@pytest.mark.live
def test_get_assessments_metadata(az, sub_ids):
    for sub_id in sub_ids:
        assessments_metadata = list(az.get_assessment_metadata(sub_id))
        for assessment_metadata in assessments_metadata:
            assert assessment_metadata.type == "Microsoft.Security/assessmentMetadata"


@pytest.mark.live
def test_get_assessment_metadata(az, sub_ids):
    for sub_id in sub_ids:
        assessment_metadata = az.get_assessment_metadata(sub_id)
        assert assessment_metadata


@pytest.mark.skip(reason="Azure API response doesn't match documentation")
def test_get_contacts(acd, sub_ids):
    for sub_id in sub_ids:
        contacts = acd.get_contacts(sub_id)
        assert contacts


@pytest.mark.live
def test_arg_get_resource_groups(az, ew, sub_ids):
    for sub_id in sub_ids:
        rgs = az.get_resource_groups(sub_id)
        assert rgs
