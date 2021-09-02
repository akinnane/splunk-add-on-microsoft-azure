
# encoding = utf-8

import os
import sys
import time
import datetime
import json
import requests
import ta_azure_utils.utils as azutil
import ta_azure_utils.auth as azauth

def validate_input(helper, definition):
    pass

def collect_events(helper, ew):
    global_account = helper.get_arg("azure_app_account")
    client_id = global_account["username"]
    client_secret = global_account["password"]
    tenant_id = helper.get_arg("tenant_id")
    subscription_id = helper.get_arg("subscription_id")
    source_type = helper.get_arg("recommendation_sourcetype")
    
    environment = helper.get_arg("environment")
    if(environment == "gov"):
        management_base_url = "https://management.usgovcloudapi.net"
    else:
        management_base_url = "https://management.azure.com"
    
    access_token = azauth.get_mgmt_access_token(client_id, client_secret, tenant_id, environment, helper)
    
    if(access_token):
        url = management_base_url + "/subscriptions/%s/providers/Microsoft.Consumption/reservationRecommendations?api-version=2019-05-01" % subscription_id
        
        try:
            recommendations = azutil.get_items(helper, access_token, url)
        
            for recommendation in recommendations:
                event = helper.new_event(
                    data=json.dumps(recommendation),
                    source=helper.get_input_type(), 
                    index=helper.get_output_index(),
                    sourcetype=source_type)
                ew.write_event(event)
        except Exception as e:
            raise e
    else:
        raise RuntimeError("Unable to obtain access token. Please check the Client ID, Client Secret, and Tenant ID")