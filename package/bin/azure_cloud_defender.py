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
import json
import os
import sys

import import_declare_test

from splunklib import modularinput as smi
from splunktaucclib.modinput_wrapper import base_modinput as base_mi

import ta_azure_utils.auth as azauth
import ta_azure_utils.utils as azutils

bin_dir = os.path.basename(__file__)


class ModInputAzureCloudDefender(base_mi.BaseModInput):
    def __init__(self):
        use_single_instance = False
        super().__init__("ta_ms_aad", "azure_cloud_defender", use_single_instance)
        self.global_checkbox_fields = None
        self.session = None

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
        return scheme

    def get_app_name(self):
        return "TA-MS-AAD"

    def validate_input(self, definition):
        pass

    def get_session(self):
        """Create an Azure session"""
        self.logger.debug("Getting Azure session")
        if self.session:
            return self.session

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
        check_point_key = f"asc_alert_last_date_{self.get_input_stanza_names()}"
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

    def get_tasks(self, subscription_id):
        """Get security center tasks"""
        check_point_key = f"asc_tasks_last_date_{self.get_input_stanza_names()}"
        check_point = self.get_check_point(check_point_key)
        url = self.task_url(subscription_id, check_point)
        event_date_key = "lastStateChangeTimeUtc"
        tasks = self.get_items_checkpoint(url, check_point_key, event_date_key)
        self.log_debug(
            f"get_tasks() check_point_key={check_point_key} check_point={check_point} url={url} tasks={len(tasks)}"
        )
        return tasks

    def get_items(self, url):
        """Get all items from an endpoint"""
        response = azutils.get_items_batch_session(
            helper=self, url=url, session=self.get_session()
        )

        items = None if response is None else response["value"]

        events = []
        while items:
            events += items

            response = azutils.handle_nextLink(
                helper=self, response=response, session=self.get_session()
            )

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

    def collect_events(self, event_writer):
        """Poll for all subscriptions then iterrate through each and get alerts and tasks"""
        subscripitons = self.get_subscriptions()

        if self.get_arg("collect_subscriptions"):
            self.write_events(event_writer, subscripitons, self.subscription_metadata())

        if self.get_arg("collect_security_center_alerts"):
            for subscription_id in self.subscription_ids(subscripitons):
                alerts = self.get_alerts(subscription_id)

            self.write_events(event_writer, alerts, self.alert_metadata())

        if self.get_arg("collect_security_center_tasks"):
            for subscription_id in self.subscription_ids(subscripitons):
                tasks = self.get_tasks(subscription_id)

            self.write_events(event_writer, tasks, self.alert_metadata())

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
