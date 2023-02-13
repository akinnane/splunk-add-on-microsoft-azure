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
from datetime import datetime, timedelta

import import_declare_test
import requests
import ta_azure_utils.auth as azauth
import ta_azure_utils.utils as azutils
from splunklib import modularinput as smi
from splunktaucclib.modinput_wrapper import base_modinput as base_mi
import time

bin_dir = os.path.basename(__file__)


class ModInputAzureCloudDefender(base_mi.BaseModInput):
    def __init__(self):
        use_single_instance = False
        super().__init__("ta_ms_aad", "azure_cloud_defender", use_single_instance)
        self.global_checkbox_fields = None
        self.session = None
        self.session_start_time = datetime.now()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=40)

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
        scheme.add_argument(
            smi.Argument(
                "collect_subscriptions",
                title="Collect Subscriptions",
                description="Should not be used",
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "source_type",
                title="Subscription Sourcetype",
                description="",
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "collect_security_center_alerts",
                title="Collect Security Center Alerts",
                description="",
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "security_alert_sourcetype",
                title="Security Alert Sourcetype",
                description="",
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "collect_security_center_tasks",
                title="Collect Security Center Tasks",
                description="",
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "security_task_sourcetype",
                title="Security Task Sourcetype",
                description="",
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "collect_security_assessments",
                title="Collect Security Assessments",
                description="",
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "security_assessment_sourcetype",
                title="Security Assessment Sourcetype",
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

    def get_session(self):
        """Create an Azure session"""
        self.logger.debug("Getting Azure session")

        session_timedout = (
            timedelta(minutes=30) > self.session_start_time - datetime.now()
        )

        if self.session and session_timedout:
            return self.session

        self.logger.debug("Creating Azure session")

        global_account = self.get_arg("azure_app_account")
        tenant_id = self.get_arg("tenant_id")
        environment = self.get_arg("environment")

        session = azauth.get_mgmt_session(
            global_account["username"],
            global_account["password"],
            tenant_id,
            environment,
            self,
        )

        if not session:
            raise RuntimeError("No Azure Session")

        self.session = session
        self.session_start_time = datetime.now()

        return session

    def management_base_url(self):
        environment = self.get_arg("environment")
        return azutils.get_environment_mgmt(environment)

    def tenant_id(self):
        self.get_arg("tenant_id")

    def subscripiton_url(self):
        return f"{self.management_base_url()}/subscriptions?api-version=2020-01-01"

    def subscription_metadata(self):
        return {
            "sourcetype": self.get_arg("source_type"),
            "index": self.get_output_index(),
            "source": f"{self.input_type}:tenant_id:{self.tenant_id()}",
        }

    def subscription_ids(self, subscripitons):
        return [subscripiton["subscriptionId"] for subscripiton in subscripitons]

    def get_subscriptions(self):
        """Get all Azure subscriptions"""
        url = self.subscripiton_url()
        subscriptions = self.get_items(url)
        self.logger.debug("subscriptions: %s", len(subscriptions))
        return subscriptions

    def alert_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts?api-version=2021-01-01"
        if check_point:
            url += f"&$filter=Properties/DetectedTimeUtc gt {check_point}"
        return url

    def alert_metadata(self):
        """Metadata for Defender Alert Splunk ingestion"""
        return {
            "sourcetype": self.get_arg("security_alert_sourcetype"),
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }

    def get_alerts(self, subscription_id):
        check_point_key = (
            f"asc_alert_last_date_{self.get_input_stanza_names()}_{subscription_id}"
        )
        check_point = self.get_check_point(check_point_key)
        url = self.alert_url(subscription_id, check_point)
        event_date_key = "timeGeneratedUtc"
        alerts = self.get_items_checkpoint(url, check_point_key, event_date_key)
        self.log_debug(
            f"get_alerts() check_point_key={check_point_key} check_point={check_point}, url={url}, alerts={len(alerts)}"
        )
        return alerts

    def task_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/tasks?api-version=2015-06-01-preview"
        if check_point:
            url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
        return url

    def task_metadata(self):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            "sourcetype": self.get_arg("security_task_sourcetype"),
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }

    def get_tasks(self, subscription_id, use_check_point=True):
        """Get security center tasks"""
        check_point_key = (
            f"asc_tasks_last_date_{self.get_input_stanza_names()}_{subscription_id}"
        )
        check_point = self.get_check_point(check_point_key if use_check_point else None)
        url = self.task_url(subscription_id, check_point)
        event_date_key = "lastStateChangeTimeUtc"
        tasks = self.get_items_checkpoint(url, check_point_key, event_date_key)
        self.log_debug(
            f"get_tasks() check_point_key={check_point_key} check_point={check_point} url={url} tasks={len(tasks)}"
        )
        return tasks

    def assessments_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
        if check_point:
            url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
        return url

    def assessments_metadata(self, subscription_id):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            "sourcetype": self.get_arg("security_assessment_sourcetype"),
            "index": self.get_output_index(),
            "source": f"{self.input_type}:{subscription_id}",
        }

    def get_assessments(self, subscription_id):
        """Get security center tasks"""
        # check_point_key = f"asc_tasks_last_date_{self.get_input_stanza_names()}"
        # check_point = self.get_check_point(check_point_key)
        url = self.assessments_url(subscription_id, None)
        # event_date_key = "lastStateChangeTimeUtc"
        tasks = self.get_items(url)
        self.log_debug(f"get_tasks() url={url} tasks={len(tasks)}")
        return tasks

    def sub_assessments_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview"
        # if check_point:
        #     url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
        return url

    def sub_assessments_metadata(self, sub_id):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            # "sourcetype": self.get_arg("security_assessment_sourcetype"),
            "sourcetype": "azure:security:sub_assessments",
            "index": self.get_output_index(),
            "source": f"{self.input_type}:{sub_id}",
        }

    def sub_assessment_metadata(self, sub_id, assessment_id):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            # "sourcetype": self.get_arg("security_assessment_sourcetype"),
            "sourcetype": "azure:security:sub_assessment",
            "index": self.get_output_index(),
            "source": f"{self.input_type}:subscription:{sub_id}:assessment_id:{assessment_id}",
        }

    def task_sub_assessment_metadata(self, sub_id, task_id):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            # "sourcetype": self.get_arg("security_assessment_sourcetype"),
            "sourcetype": "azure:security:sub_assessment",
            "index": self.get_output_index(),
            "source": f"{self.input_type}:subscription:{sub_id}:task_id:{task_id}",
        }

    def get_sub_assessments(self, subscription_id):
        """Get security center tasks"""
        # check_point_key = f"asc_tasks_last_date_{self.get_input_stanza_names()}"
        # check_point = self.get_check_point(check_point_key)
        url = self.sub_assessments_url(subscription_id, None)
        # event_date_key = "lastStateChangeTimeUtc"
        tasks = self.get_items(url)
        self.log_debug(f"get_sub_assessments() url={url} tasks={len(tasks)}")
        return tasks

    def sub_assessment_url(self, subscription_id, assessment_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments/{assessment_id}/subAssessments?api-version=2019-01-01-preview"
        return url

    def get_sub_assessment(self, url):
        """Get security center tasks"""
        url = f"{self.management_base_url()}{url}?api-version=2019-01-01-preview"
        self.log_debug(f"AK get_sub_assessment() url={url}")
        try:
            sub_assessment = self.get_items(url)
        except requests.exceptions.HTTPError as e:
            self.log_error(
                f"get_sub_assessment() ERROR getting subassessments from url={url} exception:{e}"
            )
            sub_assessment = [
                {
                    "AK_ERROR": "ERROR getting sub assesments",
                    "url": str(url),
                    "error": str(e),
                }
            ]
        self.log_debug(f"get_sub_assessment() url={url} tasks={len(sub_assessment)}")
        return sub_assessment

    def assessment_metadata_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/assessmentMetadata?api-version=2020-01-01"
        # if check_point:
        #     url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
        return url

    def assessment_metadata_metadata(self, subscription_id):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            # "sourcetype": self.get_arg("security_assessment_sourcetype"),
            "sourcetype": "azure:security:assessment_metadata",
            "index": self.get_output_index(),
            "source": f"{self.input_type}:{subscription_id}",
        }

    def get_assessment_metadata(self, subscription_id):
        """Get security center tasks"""
        # check_point_key = f"asc_tasks_last_date_{self.get_input_stanza_names()}"
        # check_point = self.get_check_point(check_point_key)
        url = self.assessment_metadata_url(subscription_id, None)
        # event_date_key = "lastStateChangeTimeUtc"
        assessment_metadata = self.get_items(url)
        self.log_debug(
            f"get_assessment_metadata() url={url} tasks={len(assessment_metadata)}"
        )
        return assessment_metadata

    # def assessments_url(self, subscription_id, check_point=None):
    #     url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
    #     if check_point:
    #         url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
    #     return url

    # def assessments_metadata(self, subscription_id):
    #     """Metadata for Defender Task Splunk ingestion"""
    #     return {
    #         "sourcetype": self.get_arg("security_assessment_sourcetype"),
    #         "index": self.get_output_index(),
    #         "source": f"{self.input_type}:{subscription_id}",
    #     }

    # def get_assessments(self, subscription_id):
    #     """Get security center tasks"""
    #     # check_point_key = f"asc_tasks_st_date_{self.get_input_stanza_names()}"
    #     # check_point = self.get_check_point(check_point_key)
    #     url = self.assessments_url(subscription_id, None)
    #     # event_date_key = "lastStateChangeTimeUtc"
    #     assessments = self.get_items(url)
    #     self.log_debug(f"get_assessments() url={url} tasks={len(assessments)}")
    #     return assessments

    def contacts_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.SecuritysecurityContacts?api-version=2020-01-01-preview"
        if check_point:
            url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
        return url

    def contacts_metadata(self):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            "sourcetype": "azure:security:contacts",
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }

    def get_contacts(self, subscription_id):
        """Get security center tasks"""
        # check_point_key = f"asc_tasks_last_date_{self.get_input_stanza_names()}"
        # check_point = self.get_check_point(check_point_key)
        url = self.contacts_url(subscription_id, None)
        # event_date_key = "lastStateChangeTimeUtc"

        contacts = self.get_items(url)
        self.log_debug(f"get_contacts() url={url} tasks={len(contacts)}")
        return contacts

    def secure_score_url(self, subscription_id, check_point=None):
        url = f"{self.management_base_url()}/subscriptions/{subscription_id}/providers/Microsoft.Security/secureScores?api-version=2020-01-01"
        if check_point:
            url += f"&$filter=Properties/LastStateChangeTimeUtc gt {check_point}"
        return url

    def secure_score_metadata(self):
        """Metadata for Defender Task Splunk ingestion"""
        return {
            "sourcetype": "azure:security:secure_score",
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }

    def get_secure_score(self, subscription_id):
        """Get security center tasks"""
        # check_point_key = f"asc_tasks_last_date_{self.get_input_stanza_names()}"
        # check_point = self.get_check_point(check_point_key)
        url = self.secure_score_url(subscription_id, None)
        # event_date_key = "lastStateChangeTimeUtc"
        secure_score = self.get_items(url)
        self.log_debug(f"get_secure_score() url={url} tasks={len(secure_score)}")
        return secure_score

    def get_items(self, url):
        """Get all items from an endpoint"""
        try_count = 0
        while True:
            try:
                response = azutils.get_items_batch_session(
                    helper=self, url=url, session=self.get_session()
                )
                break
            except Exception as e:
                self.logger.warn(str(e))
                if try_count > 3:
                    raise e
                try_count += 1
                continue

        items = None if response is None else response["value"]

        events = []
        while items:
            events += items

            try_count = 0
            while True:
                try:
                    response = azutils.handle_nextLink(
                        helper=self, response=response, session=self.get_session()
                    )
                    break
                except Exception as e:
                    self.logger.warn(str(e))
                    if try_count > 3:
                        raise e
                    try_count += 1
                    continue

            items = None if response is None else response["value"]

        return events

    def get_items_checkpoint(self, url, check_point_key, event_date_key):
        """Get an item collection using a k/v checkpoint to only retrieve the
        most recent items"""
        response = azutils.get_items_batch_session(
            helper=self, url=url, session=self.get_session()
        )

        items = None if response is None else response["value"]

        check_point = self.get_check_point(check_point_key)

        max_asc_event_date = check_point if check_point else ""

        events = []
        while items:
            for item in items:
                # Keep track of the largest detected date/time
                detected_time = item["properties"][event_date_key]
                if detected_time > max_asc_event_date:
                    max_asc_event_date = detected_time

            events += items

            self.save_check_point(check_point_key, max_asc_event_date)

            response = azutils.handle_nextLink(
                helper=self, response=response, session=self.session
            )

            items = None if response is None else response["value"]

        return events

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

    def smash_events(self):

        return_value = {}

        return_value.update({"tasks": {}})
        return_value.update({"assessments": {}})
        return_value.update({"assessment_metadata": {}})

        subscriptions = self.get_subscriptions()

        for subscription_id in self.subscription_ids(subscriptions):

            assessments = self.get_assessments(subscription_id)
            return_value["assessments"].update({subscription_id: assessments})

            assessment_metadata = self.get_assessment_metadata(subscription_id)
            return_value["assessment_metadata"].update(
                {subscription_id: assessment_metadata}
            )

            for assessment in assessments:
                assessment_sub_assessments_link = (
                    assessment.get("properties", {})
                    .get("additionalData", {})
                    .get("subAssessmentsLink", "")
                )

                if not assessment_sub_assessments_link:
                    continue

                assessment.update(
                    {"meta": {"sub_assessments_link": assessment_sub_assessments_link}}
                )

                assessment_sub_assessments = self.get_sub_assessment(
                    assessment_sub_assessments_link
                )

                assessment.get("meta").update(
                    {"sub_assessments": len(assessment_sub_assessments)}
                )
                if not assessment_sub_assessments:
                    continue

                #     assessment_sub_assessments = [
                #         i.update({"AK_SOURCE": f"assessment_id:{assessment['id']}"})
                #         for i in assessment_sub_assessments
                #     ]

                assessment.update({"sub_assessments": assessment_sub_assessments})

            tasks = self.get_tasks(subscription_id, use_check_point=False)
            return_value["tasks"].update({subscription_id: tasks})

            for task in tasks:
                details = (
                    task.get("properties", {})
                    .get("securityTaskParameters", {})
                    .get("details", [])
                )

                task.update({"meta": {"details": len(details)}})

                sub_assessment_link = next(
                    (
                        detail["value"]
                        for detail in details
                        if detail["name"] == "subAssessmentsLink"
                    ),
                    None,
                )

                if not sub_assessment_link:
                    task.get("meta").update({"no_sub_assessments_link_detected": True})
                    continue

                task.get("meta").update({"sub_assessments_link": sub_assessment_link})
                task_sub_assessments = self.get_sub_assessment(sub_assessment_link)

                task.get("meta").update({"sub_assessments": len(task_sub_assessments)})
                if not task_sub_assessments:
                    continue

                # task_sub_assessments = [
                #     i.update({"AK_TASK_SOURCE": f"task_id:{task['id']}"})
                #     for i in task_sub_assessments
                # ]

                task.update({"sub_assessments": task_sub_assessments})

        return return_value

    def smash_assessment_sub_assessment(self, assessment):
        assessment_sub_assessments_link = (
            assessment.get("properties", {})
            .get("additionalData", {})
            .get("subAssessmentsLink", "")
        )
        assessment["meta"] = {}

        assessment["meta"].update(
            {"sub_assessments_link_detected": bool(assessment_sub_assessments_link)}
        )
        if not assessment_sub_assessments_link:
            return assessment

        assessment["meta"].update(
            {"assessment_sub_assessments_link": assessment_sub_assessments_link}
        )

        assessment_sub_assessments = self.get_sub_assessment(
            assessment_sub_assessments_link
        )

        assessment.get("meta").update(
            {"sub_assessments": len(assessment_sub_assessments)}
        )

        if not assessment_sub_assessments:
            return assessment

        assessment.update({"sub_assessments": assessment_sub_assessments})

        return assessment

    def smash_task_sub_assessments(self, task):
        details = (
            task.get("properties", {})
            .get("securityTaskParameters", {})
            .get("details", [])
        )

        task.update({"meta": {"details": len(details)}})

        sub_assessment_link = next(
            (
                detail["value"]
                for detail in details
                if detail["name"] == "subAssessmentsLink"
            ),
            None,
        )

        task.get("meta").update(
            {"task_sub_assessments_link_detected": bool(sub_assessment_link)}
        )
        if not sub_assessment_link:
            return task

        task.get("meta").update({"sub_assessments_link": sub_assessment_link})
        task_sub_assessments = self.get_sub_assessment(sub_assessment_link)

        task.get("meta").update({"sub_assessments": len(task_sub_assessments)})
        if not task_sub_assessments:
            return task

            # task_sub_assessments = [
            #     i.update({"AK_TASK_SOURCE": f"task_id:{task['id']}"})
            #     for i in task_sub_assessments
            # ]

        task.update({"sub_assessments": task_sub_assessments})
        return task

    def smash_events_subscription(self, subscription_id):
        return_value = {}
        return_value.update({"tasks": {}})
        return_value.update({"assessments": {}})
        return_value.update({"assessment_metadata": {}})

        assessments = self.executor.submit(self.get_assessments, subscription_id)
        tasks = self.executor.submit(
            self.get_tasks, subscription_id, use_check_point=False
        )
        assessment_metadata = self.executor.submit(
            self.get_assessment_metadata, subscription_id
        )

        assessments = assessments.result()
        assessments = list(
            self.executor.map(self.smash_assessment_sub_assessment, assessments)
        )

        self.logger.debug(
            f"smash_events_subscriptions():len(assessments) = {len(assessments)}"
        )
        return_value["assessments"].update({subscription_id: assessments})

        tasks = tasks.result()
        tasks = list(self.executor.map(self.smash_task_sub_assessments, tasks))
        return_value["tasks"].update({subscription_id: tasks})

        return_value["assessment_metadata"].update(
            {subscription_id: assessment_metadata.result()}
        )

        return return_value

    def smash_events_threaded(self):
        subscriptions = self.get_subscriptions()
        return_value = {}
        return_value.update({"tasks": {}})
        return_value.update({"assessments": {}})
        return_value.update({"assessment_metadata": {}})

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for subscription_id in self.subscription_ids(subscriptions):
                results.append(
                    executor.submit(self.smash_events_subscription, subscription_id)
                )

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for subscription_id in self.subscription_ids(subscriptions):
                results.append(
                    executor.submit(self.smash_events_subscription, subscription_id)
                )

        for r in results:
            r = r.result()
            return_value["tasks"].update(r["tasks"])
            return_value["assessments"].update(r["assessments"])
            return_value["assessment_metadata"].update(r["assessment_metadata"])

        return return_value

    def process_smashed_events(self, events):
        new = []

        used_assesments_ids = set()

        for sub_id, tasks in events["tasks"].items():

            for task in tasks:

                out = {}
                new.append(out)
                out["task"] = task

                if "assessmentKey" not in task["properties"]["securityTaskParameters"]:
                    continue

                out["assessments"] = []
                for assessment in events["assessments"][sub_id]:
                    if (
                        task["properties"]["securityTaskParameters"]["assessmentKey"]
                        in assessment["id"]
                    ) and (
                        (
                            # Task ID == Assesment Resource ID
                            task.get("properties", {})
                            .get("securityTaskParameters", {})
                            .get("resourceId", "")
                            == assessment.get("properties", {})
                            .get("resourceDetails", {})
                            .get("Id", "")
                        )
                        or (
                            # Task ID in "Assesment Resource ID/"
                            # Catch subresources but exclude resources on the same hierarchical level with simular name
                            task.get("properties", {})
                            .get("securityTaskParameters", {})
                            .get("resourceId", "")
                            + "/"
                            in assessment.get("properties", {})
                            .get("resourceDetails", {})
                            .get("Id", "")
                        )
                    ):
                        out["assessments"].append(assessment)
                    else:
                        continue

                    for metadata in events["assessment_metadata"][sub_id]:
                        if metadata["name"] in assessment["id"]:
                            assessment.update({"metadata": metadata})

                    used_assesments_ids.add(assessment["id"])

        self.logger.debug(f"events['assessments']: {len(events['assessments'])}")

        unused_assessments = {}
        for sub_id, assessments in events["assessments"].items():
            for assessment in assessments:
                if assessment["id"] not in used_assesments_ids:
                    subscription_assessments = unused_assessments.get(sub_id, [])
                    subscription_assessments.append(assessment)
                    unused_assessments[sub_id] = subscription_assessments

        self.logger.debug(
            f"assessments: {len(assessments)}, used_assessments:{used_assesments_ids}"
        )

        for sub_id, assessments in unused_assessments.items():
            for assessment in assessments:
                out = {}
                new.append(out)
                out["assessment"] = assessment
                for metadata in events["assessment_metadata"][sub_id]:
                    if metadata["name"] in assessment["id"]:
                        assessment.update({"metadata": metadata})
        return new

    def collect_events(self, event_writer):
        t1 = time.perf_counter()
        events = self.smash_events_threaded()
        t2 = time.perf_counter()
        events = self.process_smashed_events(events)
        t3 = time.perf_counter()
        metadata = {
            "sourcetype": "azure:security:finding",
            "index": self.get_output_index(),
            "source": f"{self.input_type}",
        }
        t = datetime.now().timestamp()
        for e in events:
            e["SSPHP_RUN"] = t

        self.logger.debug(
            f"events for writing: {len(events)} \nmetadata: {metadata} \nexample event: {events[0]}"
        )
        t4 = time.perf_counter()
        self.write_events(event_writer, events, metadata)
        t5 = time.perf_counter()
        self.logger.info(
            f"times: smash_events_threaded:{t2-t1}, process_smashed_events:{t3-t2}, t3-t4:{t4-t3}, write_events:{t5-t3}"
        )
        return events

    # def collect_events_old(self, event_writer):
    #     """Poll for all subscriptions then iterrate through each and get alerts and tasks"""
    #     subscriptions = self.get_subscriptions()

    #     return_value = {}

    #     if False:  # self.get_arg("collect_subscriptions"):
    #         self.write_events(event_writer, subscriptions, self.subscription_metadata())

    #     if self.get_arg("collect_security_center_alerts"):
    #         return_value.update({"alerts": {}})
    #         for subscription_id in self.subscription_ids(subscriptions):
    #             alerts = self.get_alerts(subscription_id)

    #             self.write_events(event_writer, alerts, self.alert_metadata())

    #             return_value["alerts"].update({subscription_id: alerts})

    #     if self.get_arg("collect_security_center_tasks"):
    #         return_value.update({"tasks": {}})
    #         for subscription_id in self.subscription_ids(subscriptions):
    #             tasks = self.get_tasks(subscription_id)

    #             self.write_events(event_writer, tasks, self.task_metadata())

    #             return_value["tasks"].update({subscription_id: tasks})

    #             for task in tasks:
    #                 if "properties" not in assessment:
    #                     continue
    #                 if "additionalData" not in assessment["properties"]:
    #                     continue
    #                 if (
    #                     "subAssessmentsLink"
    #                     not in assessment["properties"]["additionalData"]
    #                 ):
    #                     continue

    #                 sub_assessment = self.get_sub_assessment(
    #                     subscription_id, assessment["name"]
    #                 )

    #                 self.write_events(
    #                     event_writer,
    #                     sub_assessment,
    #                     self.sub_assessment_metadata(
    #                         subscription_id, assessment["name"]
    #                     ),
    #                 )

    #     if self.get_arg("collect_security_assessments"):
    #         return_value.update({"assessments": {}})
    #         return_value.update({"sub_assessments": {}})
    #         return_value.update({"assessment_metadata": {}})

    #         for subscription_id in self.subscription_ids(subscriptions):
    #             assessments = self.get_assessments(subscription_id)
    #             self.write_events(
    #                 event_writer,
    #                 assessments,
    #                 self.assessments_metadata(subscription_id),
    #             )

    #             return_value["assessments"].update({subscription_id: assessments})

    #             for assessment in assessments:
    #                 if "properties" not in assessment:
    #                     continue
    #                 if "additionalData" not in assessment["properties"]:
    #                     continue
    #                 if (
    #                     "subAssessmentsLink"
    #                     not in assessment["properties"]["additionalData"]
    #                 ):
    #                     continue

    #                 sub_assessment = self.get_sub_assessment(
    #                     subscription_id, assessment["name"]
    #                 )

    #                 self.write_events(
    #                     event_writer,
    #                     sub_assessment,
    #                     self.sub_assessment_metadata(
    #                         subscription_id, assessment["name"]
    #                     ),
    #                 )

    #             sub_assessments = self.get_sub_assessments(subscription_id)
    #             self.write_events(
    #                 event_writer,
    #                 sub_assessments,
    #                 self.sub_assessments_metadata(subscription_id),
    #             )
    #             return_value["sub_assessments"].update(
    #                 {subscription_id: sub_assessments}
    #             )

    #             assessment_metadata = self.get_assessment_metadata(subscription_id)
    #             self.write_events(
    #                 event_writer,
    #                 assessment_metadata,
    #                 self.assessment_metadata_metadata(subscription_id),
    #             )
    #             return_value["assessment_metadata"].update(
    #                 {subscription_id: assessment_metadata}
    #             )

    #     # Azure API response doesn't match documentation
    #     # https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?tabs=HTTP
    #     if False:
    #         return_value.update({"contacts": {}})
    #         for subscription_id in self.subscription_ids(subscriptions):
    #             contacts = self.get_contacts(subscription_id)

    #             self.write_events(event_writer, contacts, self.contacts_metadata())
    #             return_value["contacts"].update({subscription_id: contacts})

    #     if True:
    #         return_value.update({"secure_score": {}})
    #         for subscription_id in self.subscription_ids(subscriptions):
    #             secure_score = self.get_secure_score(subscription_id)

    #             self.write_events(
    #                 event_writer, secure_score, self.secure_score_metadata()
    #             )
    #             return_value["secure_score"].update({subscription_id: secure_score})

    #     return return_value

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
