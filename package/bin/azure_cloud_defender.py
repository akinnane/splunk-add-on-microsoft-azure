# encoding = utf-8
"""

Copyright 2020 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""
import concurrent.futures
import json
import os
import re
import sys
import time
from datetime import datetime

# import azure
import import_declare_test
from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.v2015_06_01_preview.models import SecurityTask
from azure.mgmt.security.v2021_06_01.models import SecurityAssessmentResponse
from azure.mgmt.security.v2019_01_01_preview.models import SecuritySubAssessment
from azure.mgmt.subscription import SubscriptionClient
import azure.mgmt.security
from msrestazure.tools import parse_resource_id
from splunklib import modularinput as smi
from splunktaucclib.modinput_wrapper import base_modinput as base_mi


class SecuritySubAssessment(SecuritySubAssessment):
    def __lt__(self, other):
        return self.id.cmp(other.id)

    def __hash__(self):
        return hash(self.id)


class SecurityTask(SecurityTask):
    subassessment_resource_scope_regex = re.compile(
        "(?P<scope>.*?)/providers/Microsoft.Security/assessments/(?P<assessment_name>[^/]+)/subAssessments"
    )

    def sub_assessment_resource_scope(self):
        match = self.subassessment_resource_scope_regex.search(
            self.sub_assessment_link()
        )
        return match.group("scope")

    def assessment_key(self):
        return self.security_task_parameters.additional_properties.get(
            "assessmentKey", "NOASSESSMENTKEY"
        )

    def resource_id(self):
        return self.security_task_parameters.additional_properties.get(
            "resourceId", "NORESOURCEID"
        )

    def sub_assessment_link(self):
        details = self.security_task_parameters.additional_properties.get("details", [])

        sub_assessment_link = next(
            (
                detail["value"]
                for detail in details
                if detail["name"] == "subAssessmentsLink"
            ),
            None,
        )
        return sub_assessment_link

    def subscription_id(self):
        return parse_resource_id(self.id)["subscription"]


class SecurityAssessmentResponse(SecurityAssessmentResponse):
    subassessment_resource_scope_regex = re.compile(
        "(?P<scope>.*?)/providers/Microsoft.Security/assessments/(?P<assessment_name>[^/]+)/subAssessments"
    )

    def sub_assessment_link(self):
        if self.additional_data:
            return self.additional_data.get("subAssessmentsLink", None)
        else:
            return None

    def assessment_key(self):
        return self.name

    def sub_assessment_resource_scope(self):
        match = self.subassessment_resource_scope_regex.search(
            self.sub_assessment_link()
        )
        return match.group("scope")

    def subscription_id(self):
        return parse_resource_id(self.id)["subscription"]

    def resource_id(self):
        return self.resource_details.additional_properties.get("Id", "NORESOURCEID")


sub_assessments_attribute_map = {
    # "sub_assessments": {
    #     "key": "sub_assessments",
    #     "type": "[SecuritySubAssessment]",
    # },
    "metadata": {
        "key": "properties.metadata",
        "type": "SecurityAssessmentMetadataResponse",
    },
}


SecurityAssessmentResponse._attribute_map.update(sub_assessments_attribute_map)

SecurityTask._attribute_map.update(sub_assessments_attribute_map)

azure.mgmt.security.v2019_01_01_preview.models.SecuritySubAssessment = (
    SecuritySubAssessment
)

azure.mgmt.security.v2021_06_01.models.SecurityAssessmentResponse = (
    SecurityAssessmentResponse
)

azure.mgmt.security.v2015_06_01_preview.models.SecurityTask = SecurityTask

azure.mgmt.security.v2015_06_01_preview.models.SecurityTask.enable_additional_properties_sending()
azure.mgmt.security.v2015_06_01_preview.models.SecurityTaskParameters.enable_additional_properties_sending()

azure.mgmt.security.v2019_01_01_preview.models._models_py3.AdditionalData.enable_additional_properties_sending()
azure.mgmt.security.v2019_01_01_preview.models._models_py3.AzureResourceDetails.enable_additional_properties_sending()
azure.mgmt.security.v2019_01_01_preview.models._models_py3.SubAssessmentStatus.enable_additional_properties_sending()
azure.mgmt.security.v2019_01_01_preview.models.SecuritySubAssessment.enable_additional_properties_sending()

azure.mgmt.security.v2021_06_01.models.ResourceDetails.enable_additional_properties_sending()

bin_dir = os.path.basename(__file__)


class ModInputAzureCloudDefender(base_mi.BaseModInput):
    def __init__(self):
        use_single_instance = False
        super().__init__("ta_ms_aad", "azure_cloud_defender", use_single_instance)
        self.global_checkbox_fields = None
        self.session = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=40)
        self.ssphp_run = datetime.now().timestamp()
        self._security_center = {}

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super().get_scheme()
        scheme.title = "Azure Cloud Defender"
        scheme.description = "Go to the add-on's configuration UI and configure modular inputs under the Inputs menu."
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        scheme.add_argument(
            smi.Argument("name", title="Name", description="", required_on_create=True)
        )
        scheme.add_argument(
            smi.Argument(
                "azure_app_account",
                title="Azure App Account",
                description="",
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "tenant_id",
                title="Tenant ID",
                description="",
                required_on_create=True,
                required_on_edit=False,
            )
        )
        return scheme

    def get_app_name(self):
        return "TA-MS-AAD"

    def validate_input(self, definition):
        pass

    def get_azure_creds(self):
        """Create an Azure session"""
        self.logger.debug("Getting Azure CLIENT")

        global_account = self.get_arg("azure_app_account")
        tenant_id = self.get_arg("tenant_id")
        # environment = self.get_arg("environment")

        credentials = ClientSecretCredential(
            tenant_id,
            global_account["username"],  # client ID
            client_secret=global_account["password"],
            # No provision for .gov azure
        )

        return credentials

    def security_center(self, subscription_id, caller):
        sub = self._security_center.get(subscription_id, {})
        if not sub:
            self._security_center[subscription_id] = sub
        sc = sub.get(caller, None)
        if not sc:
            sc = SecurityCenter(self.get_azure_creds(), subscription_id)
            self._security_center[subscription_id].update({caller: sc})

        return sc

    def subscription_metadata(self):
        return {
            "sourcetype": self.get_arg("source_type"),
            "index": self.get_output_index(),
            "source": f"{self.input_type}:tenant_id:{self.tenant_id()}",
        }

    def subscription_ids(self, subscripitons):
        return [subscripiton.subscription_id for subscripiton in subscripitons]

    def get_subscriptions(self):
        """Get all Azure subscriptions"""
        creds = self.get_azure_creds()
        subscriptions = SubscriptionClient(creds).subscriptions.list()
        return subscriptions

    def get_tasks(self, subscription_id):
        """Get security center tasks"""
        # sc = SecurityCenter(self.get_azure_creds(), subscription_id)
        tasks = self.security_center(subscription_id, "tasks").tasks.list()
        return tasks

    def get_assessments(self, subscription_id):
        """Get security center assessments"""
        assessments = self.security_center(
            subscription_id, "assessments"
        ).assessments.list(f"/subscriptions/{subscription_id}")
        return assessments

    def get_sub_assessments(self, has_sub_assessments):
        if not has_sub_assessments.sub_assessment_link():
            return []
        try:
            sub_assessments = self.security_center(
                has_sub_assessments.subscription_id(), "sub_assessments"
            ).sub_assessments.list(
                has_sub_assessments.sub_assessment_resource_scope(),
                has_sub_assessments.assessment_key(),
            )
        except AzureError as e:
            self.logger.error(e)
            sub_assessments = []
        return sub_assessments

    def get_assessments_metadata(self, subscription_id):
        assessment_metadata = self.security_center(
            subscription_id, "assessment_metadata"
        ).assessments_metadata.list()
        return assessment_metadata

    def write_events(self, event_writer, collection, metadata):
        """Write a collection of events using the provided eventwriter and metadata"""
        for item in collection:
            event = self.new_event(
                data=json.dumps(item),
                source=metadata["source"],
                index=metadata["index"],
                sourcetype=metadata["sourcetype"],
            )
            event_writer.write_event(event)
        sys.stdout.flush()

    def smash_has_assessments_sub_assessment(self, has_assessments):
        has_assessments.sub_assessments = list(
            self.get_sub_assessments(has_assessments)
        )
        return has_assessments

    def smash_events_subscription(self, subscription_id):
        assessments = self.executor.submit(self.get_assessments, subscription_id)

        tasks = self.executor.submit(self.get_tasks, subscription_id)
        assessment_metadata = self.executor.submit(
            self.get_assessments_metadata, subscription_id
        )

        assessments = assessments.result()
        assessments = list(
            self.executor.map(self.smash_has_assessments_sub_assessment, assessments)
        )

        tasks = tasks.result()
        tasks = list(
            self.executor.map(self.smash_has_assessments_sub_assessment, tasks)
        )

        assessment_metadata = list(assessment_metadata.result())

        self.logger.info(
            f"smash_events_subscriptions():{subscription_id} len(assessments)={len(assessments)} len(tasks)={len(tasks)} len(assessment_metadata)={len(assessment_metadata)}"
        )

        used_assessment_ids = set()

        events = []

        for task in tasks:
            event = {}
            event["task"] = task.serialize(keep_readonly=True)
            event["meta"] = {}
            event["meta"]["task"] = parse_resource_id(task.id)

            events.append(event)

            if not task.assessment_key():
                continue

            for assessment in assessments:
                if (task.assessment_key() in assessment.id) and (
                    (
                        # Task assessment key == Assesment Resource ID
                        task.resource_id()
                        == assessment.resource_id()
                    )
                    or (
                        # Task ID in "Assesment Resource ID/"
                        # Catch subresources but exclude resources on the same hierarchical level with simular name
                        task.resource_id() + "/"
                        in assessment.resource_id()
                    )
                ):
                    for metadata in assessment_metadata:
                        if metadata.name in assessment.id:
                            assessment.metadata = metadata

                    event["assessment"] = assessment.serialize(keep_readonly=True)
                    event["meta"]["assessment"] = parse_resource_id(assessment.id)
                    used_assessment_ids.add(assessment.id)

                    sub_assessments = []
                    if hasattr(task, "sub_assessments") and task.sub_assessments:
                        sub_assessments += task.sub_assessments
                        task.sub_assesments = []

                    if (
                        hasattr(assessment, "sub_assessments")
                        and assessment.sub_assessments
                    ):
                        sub_assessments += assessment.sub_assessments
                        assessment.sub_assesments = []

                    sub_assessments = [
                        sa.serialize(keep_readonly=True)
                        for sa in list(set(sub_assessments))
                    ]

                    if sub_assessments:
                        event["sub_assessments"] = sub_assessments

                else:
                    if hasattr(task, "sub_assessments") and task.sub_assessments:
                        event["sub_assessments"] = [
                            sa.serialize(keep_readonly=True)
                            for sa in task.sub_assessments
                        ]
                        task.sub_assesments = []
                    continue

        for assessment in assessments:
            if assessment.id not in used_assessment_ids:
                for metadata in assessment_metadata:
                    if metadata.name in assessment.id:
                        assessment.metadata = metadata

                event = {}
                event["meta"] = {}
                event["meta"]["assessment"] = parse_resource_id(assessment.id)
                event["assessment"] = assessment.serialize(keep_readonly=True)

                if (
                    hasattr(assessment, "sub_assessments")
                    and assessment.sub_assessments
                ):
                    event["sub_assessments"] = [
                        sa.serialize(keep_readonly=True)
                        for sa in assessment.sub_assessments
                    ]
                    assessment.sub_assesments = []

                events.append(event)

        self.logger.info(
            f"subscription_id:{subscription_id}, used_assessment_ids:{len(used_assessment_ids)}, events:{len(events)}"
        )

        return events

    def smash_events_threaded(self):
        subscriptions = self.get_subscriptions()

        results = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        for subscription_id in self.subscription_ids(subscriptions):
            results.append(
                executor.submit(self.smash_events_subscription, subscription_id)
            )

        metadata = {
            "sourcetype": "azure:security:finding",
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }

        count = 0

        for r in concurrent.futures.as_completed(results):
            r = r.result()
            for event in r:
                event["SSPHP_RUN"] = self.ssphp_run
                event1 = self.new_event(
                    data=json.dumps(event, sort_keys=True),
                    source=metadata["source"],
                    index=metadata["index"],
                    sourcetype=metadata["sourcetype"],
                )

                self.event_writer.write_event(event1)
                count += 1

        sys.stdout.flush()
        self.logger.info(f"Finished writing events: {count}")

    def collect_events(self, event_writer):
        self.event_writer = event_writer
        t1 = time.perf_counter()
        events = self.smash_events_threaded()
        t2 = time.perf_counter()
        self.logger.info(
            f"time: smash_events_threaded:{t2-t1}"  # process_smashed_events:{t3-t2}, t3-t4:{t4-t3}, write_events:{t5-t3}"
        )
        return events

    def get_account_fields(self):
        account_fields = []
        account_fields.append("azure_app_account")
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        return checkbox_fields

    def get_global_checkbox_fields(self):
        if self.global_checkbox_fields is None:
            checkbox_name_file = os.path.join(bin_dir, "global_checkbox_param.json")
            try:
                if os.path.isfile(checkbox_name_file):
                    with open(checkbox_name_file, "r") as fp:
                        self.global_checkbox_fields = json.load(fp)
                else:
                    self.global_checkbox_fields = []
            except Exception as exception:
                self.log_error(
                    "Get exception when loading global checkbox parameter names. "
                    + str(exception)
                )
                self.global_checkbox_fields = []
        return self.global_checkbox_fields


if __name__ == "__main__":
    exitcode = ModInputAzureCloudDefender().run(sys.argv)
    sys.exit(exitcode)
