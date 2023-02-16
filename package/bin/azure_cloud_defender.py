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
import sys
from datetime import datetime
import import_declare_test

from splunklib import modularinput as smi
from splunktaucclib.modinput_wrapper import base_modinput as base_mi
import time

from azure.identity import ClientSecretCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.v2021_06_01.models import SecurityAssessmentResponse
from azure.mgmt.security.v2015_06_01_preview.models import SecurityTask
from msrestazure.tools import parse_resource_id
import azure

import re


class SecurityTask(SecurityTask):
    def assessment_key(self):
        return self.security_task_parameters.additional_properties.get(
            "assessmentKey", None
        )

    def resource_id(self):
        return self.security_task_parameters.additional_properties.get(
            "resourceId", None
        )

    def subscription_id(self):
        return parse_resource_id(self.id)["subscription"]

    def add_sub_assessments_to_attribute_map(self):
        self._attribute_map.update(
            {
                "sub_assessments": {
                    "key": "sub_assessments",
                    "type": "[SecuritySubAssessment]",
                }
            }
        )
        self.__dict__.update({"sub_assessments": []})


class SecurityAssessmentResponse(SecurityAssessmentResponse):
    subassessment_resource_scope_regex = re.compile(
        "(?P<scope>.*?)/providers/Microsoft.Security/assessments/[^/]+/subAssessments"
    )

    def sub_assessment_link(self):
        if self.additional_data:
            return self.additional_data.get("subAssessmentsLink", None)
        else:
            return None

    def sub_assessment_resource_scope(self):
        match = self.subassessment_resource_scope_regex.search(
            self.sub_assessment_link()
        )
        return match.group("scope")

    def add_sub_assessments_to_attribute_map(self):
        self._attribute_map.update(
            {
                "sub_assessments": {
                    "key": "sub_assessments",
                    "type": "[SecuritySubAssessment]",
                }
            }
        )
        self.sub_assessments = []

    def subscription_id(self):
        return parse_resource_id(self.id)["subscription"]

    def resource_id(self):
        return self.resource_details.additional_properties.get("Id", None)


azure.mgmt.security.v2021_06_01.models.SecurityAssessmentResponse = (
    SecurityAssessmentResponse
)
azure.mgmt.security.v2015_06_01_preview.models.SecurityTask = SecurityTask

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
        scheme.add_argument(
            smi.Argument(
                "environment",
                title="Environment",
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

    def get_sub_assessments(self, assessment):
        if not assessment.sub_assessment_link():
            return []
        sub_assessments = self.security_center(
            assessment.subscription_id(), "sub_assessments"
        ).sub_assessments.list(
            assessment.sub_assessment_resource_scope(), assessment.name
        )
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

    def smash_assessment_sub_assessment(self, assessment):
        assessment_sub_assessments = list(self.get_sub_assessments(assessment))
        if not assessment_sub_assessments:
            return assessment
        assessment.add_sub_assessments_to_attribute_map()
        assessment.sub_assessments = assessment_sub_assessments
        return assessment

    def smash_task_sub_assessments(self, task):
        details = task.security_task_parameters.additional_properties.get("details", [])

        sub_assessment_link = next(
            (
                detail["value"]
                for detail in details
                if detail["name"] == "subAssessmentsLink"
            ),
            None,
        )

        if not sub_assessment_link:
            return task

        task_sub_assessments = self.get_sub_assessments(sub_assessment_link)

        if not task_sub_assessments:
            return task

        task.add_sub_assessments_to_attribute_map()
        task.update({"sub_assessments": task_sub_assessments})
        return task

    def smash_events_subscription(self, subscription_id):
        return_value = {}
        return_value.update({"tasks": {}})
        return_value.update({"assessments": {}})
        return_value.update({"assessment_metadata": {}})

        assessments = self.executor.submit(self.get_assessments, subscription_id)

        tasks = self.executor.submit(self.get_tasks, subscription_id)
        assessment_metadata = self.executor.submit(
            self.get_assessments_metadata, subscription_id
        )

        assessments = assessments.result()
        assessments = list(
            self.executor.map(self.smash_assessment_sub_assessment, assessments)
        )

        return_value["assessments"].update({subscription_id: assessments})

        tasks = tasks.result()
        tasks = list(self.executor.map(self.smash_task_sub_assessments, tasks))
        return_value["tasks"].update({subscription_id: tasks})

        return_value["assessment_metadata"].update(
            {subscription_id: assessment_metadata.result()}
        )

        self.logger.info(
            f"smash_events_subscriptions():{subscription_id} len(assessments)={len(assessments)} len(tasks)={len(tasks)}"
        )

        used_assesments_ids = set()

        new = []

        for sub_id, tasks in return_value["tasks"].items():
            for task in tasks:
                out = {}
                new.append(out)
                out["task"] = task.as_dict()
                out["meta"] = parse_resource_id(task.id)

                if not task.assessment_key():
                    continue

                for assessment in return_value["assessments"][sub_id]:
                    if (task.assessment_key() in assessment.resource_id()) and (
                        (
                            # Task ID == Assesment Resource ID
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
                        for metadata in return_value["assessment_metadata"][sub_id]:
                            if metadata.name in assessment.id:
                                assessment.update({"metadata": metadata})

                        out_assessments = out.get("assessments", [])
                        out_assessments.append(assessment)
                        out["assessments"] = out_assessments.as_dict()
                        used_assesments_ids.add(assessment.id)
                    else:
                        continue

        self.logger.debug(
            f"sub_id:{sub_id}, return_value['assessments']: {len(return_value['assessments'])}"
        )

        used_assessments = {}
        for sub_id, assessments in return_value["assessments"].items():
            for assessment in assessments:
                if assessment.id not in used_assesments_ids:
                    subscription_assessments = used_assessments.get(sub_id, [])
                    subscription_assessments.append(assessment)
                    used_assessments[sub_id] = subscription_assessments

        for sub_id, assessments in used_assessments.items():
            for assessment in assessments:
                for metadata in return_value["assessment_metadata"][sub_id]:
                    if metadata.name in assessment.id:
                        assessment.metadata = metadata
                out = {}
                out["meta"] = parse_resource_id(assessment.id)
                out["assessments"] = []
                out["assessments"].append(assessment.as_dict())
                new.append(out)

        self.logger.error(
            f"sub_id:{sub_id}, assessments:{len(assessments)}, used_assessments:{len(used_assessments[sub_id])} new:{len(new)}"
        )

        return new

    def smash_events_threaded(self):
        subscriptions = self.get_subscriptions()

        results = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        for subscription_id in self.subscription_ids(subscriptions):
            results.append(
                executor.submit(self.smash_events_subscription, subscription_id)
            )

        self.logger.info(f"results:{len(results)}")

        metadata = {
            "sourcetype": "azure:security:finding",
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }

        for r in results:
            r = r.result()
            for event in r:
                event["SSPHP_RUN"] = self.ssphp_run
                event = self.new_event(
                    data=json.dumps(event),
                    source=metadata["source"],
                    index=metadata["index"],
                    sourcetype=metadata["sourcetype"],
                )
                self.event_writer.write_event(event)

    def collect_events(self, event_writer):
        self.event_writer = event_writer
        t1 = time.perf_counter()
        events = self.smash_events_threaded()
        t2 = time.perf_counter()
        self.logger.info(
            f"times: smash_events_threaded:{t2-t1}"  # process_smashed_events:{t3-t2}, t3-t4:{t4-t3}, write_events:{t5-t3}"
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
