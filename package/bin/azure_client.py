from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.resource.subscriptions import SubscriptionClient


class AzureClient:
    def __init__(self, *args, **kwargs):
        self._credentials = None
        self._security_center = {}
        super().__init__(*args, **kwargs)

    def get_azure_credentials(self):
        """Create an Azure session"""
        if self._credentials:
            return self._credentials

        global_account = self.get_arg("azure_app_account")
        tenant_id = self.get_arg("tenant_id")

        self._credentials = ClientSecretCredential(
            tenant_id,
            global_account["username"],  # client ID
            client_secret=global_account["password"],
            # No provision for .gov azure
        )

        return self._credentials

    def security_center(self, subscription_id, caller):
        sc = self._security_center.setdefault(subscription_id, {}).get(caller, None)

        if not sc:
            sc = SecurityCenter(self.get_azure_credentials(), subscription_id)
            self._security_center[subscription_id].update({caller: sc})

        return sc

    def get_subscriptions(self):
        subscriptions = SubscriptionClient(
            self.get_azure_credentials()
        ).subscriptions.list()
        return subscriptions

    def subscription_ids(self, subscripitons):
        return [subscripiton.subscription_id for subscripiton in subscripitons]

    def get_resource_groups(self, subscription_id):
        resource_groups = ResourceManagementClient(
            self.get_azure_credentials(), subscription_id
        ).resource_groups.list()
        return list(resource_groups)

    def get_assessments(self, subscription_id):
        """Get security center assessments"""
        assessments = self.security_center(
            subscription_id, "assessments"
        ).assessments.list(f"/subscriptions/{subscription_id}")
        return assessments

    def get_all_sub_assessments(self, subscription_id):
        """Get security center assessments"""
        assessments = self.security_center(
            subscription_id, "sub_assessments"
        ).sub_assessments.list_all(f"/subscriptions/{subscription_id}")
        return assessments

    def get_assessment_metadata(self, subscription_id):
        assessment_metadata = self.security_center(
            subscription_id, "assessment_metadata"
        ).assessments_metadata.list()
        return assessment_metadata
