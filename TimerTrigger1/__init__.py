from .api_client import get_access_token
import requests
import json
import datetime
from requests.auth import HTTPBasicAuth
import azure.functions as func
import base64
import hmac
import hashlib
import os
import logging
import re
from .state_manager import StateManager

# Client ID and client password for Cisco Basic Authentication
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
CISCO_CUSTOMER_ID = os.environ['CISCO_CUSTOMER_ID']
CUSTOMER_ID = os.environ['WorkspaceID']
SHARED_KEY = os.environ['WorkspaceKey']
CONNECTION_STRING = os.environ['AzureWebJobsStorage']
AUTH_TOKEN = ""
log_type = 'CiscoGlobalThreatAlerts'
BASE_URL = "https://api.cta.eu.amp.cisco.com"
logAnalyticsUri = os.environ.get('logAnalyticsUri')

# Validate loganalyticsuri
if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):
    logAnalyticsUri = 'https://' + CUSTOMER_ID + '.ods.opinsights.azure.com'

pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
match = re.match(pattern, str(logAnalyticsUri))
if (not match):
    raise Exception("Invalid Log Analytics Uri.")

# Get the access token
token_response = get_access_token(CLIENT_ID, CLIENT_SECRET)

# Check the response
if "error" in token_response:
    logging.error("Error in getting auth token:", token_response["error"], token_response["message"])
else:
    logging.info("1. Token obtained successfully")
    AUTH_TOKEN = token_response['access_token']

# generate date
def generate_date():
    current_time = datetime.datetime.utcnow().replace(second=0, microsecond=0) - \
        datetime.timedelta(minutes=10)
    state = StateManager(connection_string=CONNECTION_STRING)
    past_time = state.get()
    if past_time is not None:
        logging.info("2. The last time point is: {}".format(past_time))
    else:
        logging.info(
            "2. There is no last time point, trying to get events for last hour.")
        past_time = (current_time - datetime.timedelta(minutes=60)
                     ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    state.post(current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    return (past_time, current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

# build signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + \
        str(content_length) + "\n" + content_type + \
        "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(
        decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization

#post data to log analytics ws 
def post_data(body):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(
        CUSTOMER_ID, SHARED_KEY, rfc1123date, content_length, method, content_type, resource)
    uri = logAnalyticsUri + resource + "?api-version=2016-04-01"
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        return response.status_code
    else:
        logging.warn("Events are not processed into Azure. Response code: {}".format(
            response.status_code))
        return None

#get cisco encriched alerts
def get_enriched_cisco_threat_alerts(date):
    events = []
    threat_detection_ids = []
    alert_ids = []
    cached_context_objects = {}

    # 1. get all Events in stable order ensured by `modificationSequenceNumber` 
    events_url = f"{BASE_URL}/threat-detection/customer/{CISCO_CUSTOMER_ID}/enriched-events-with-threat-detection-ids?detectedOrModifiedAfter={date[0]}"
    events_params = {
        "sort": "modificationSequenceNumber",
    }
    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Accept": "application/json",
    }

    logging.info("Cisco API 1. Getting enriched events with threat detection ids")
    events_response = requests.get(events_url, params=events_params, headers=headers)
    
    try:
        events_data = events_response.json()
    except json.decoder.JSONDecodeError as e:
        print(f"JSONDecodeError: {e}")
        print("Raw Response Content:")
        print(events_response.text)
        return

    # extract references to threat detections and keep them for final processing
    for event in events_data.get("items", []):
        events.append(event)
        threat_detection_ids.extend(event.get("threatDetectionIds", []))

    # bulk load threat detections
    threat_detections_url = f"{BASE_URL}/alert-management/customer/{CISCO_CUSTOMER_ID}/enriched-threat-detections-with-alert-ids/search"
    threat_detections_params = {
        "filter": {
            "threatDetectionIds": list(set(threat_detection_ids))
        }
    }
    logging.info("Cisco API 2. Getting enriched threat detections with alert ids from threat detection ID's")
    threat_detections_response = requests.post(threat_detections_url, json=threat_detections_params, headers=headers)
    
    try:
        threat_detections_data = threat_detections_response.json()
    except json.decoder.JSONDecodeError as e:
        logging.warn(f"JSONDecodeError: {e}")
        print("Raw Response Content:")
        print(threat_detections_response.text)
        return

    # extract references to alerts and keep threat detections in cache key=ID, value=OBJECT
    for threat_detection in threat_detections_data.get("items", []):
        cached_context_objects[threat_detection.get("id")] = threat_detection
        alert_ids.extend(threat_detection.get("alertIds", []))

    # bulk load alerts
    alerts_url = f"{BASE_URL}/alert-management/customer/{CISCO_CUSTOMER_ID}/alerts/search"
    alerts_params = {
        "filter": {
            "alertIds": list(set(alert_ids))
        }
    }

    logging.info("Cisco API 3. Getting alerts from alert ids")
    alerts_response = requests.post(alerts_url, json=alerts_params, headers=headers)
    
    try:
        alerts_data = alerts_response.json()
    except json.decoder.JSONDecodeError as e:
        print(f"JSONDecodeError: {e}")
        print("Raw Response Content:")
        print(alerts_response.text)
        return

    # keep alerts in cache key=ID, value=OBJECT
    for alert in alerts_data.get("items", []):
        cached_context_objects[alert.get("id")] = alert

    # Prepare the results dictionary
    results = {
        "cached_context_objects": cached_context_objects,
    }

    return results

def convert_to_array(data):
    result = []
    logging.info("Converting restults to list")
    for key in data:
        result.append(data[key])
        
    return result

def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    # get time from state
    time = generate_date()
    # get events
    results = get_enriched_cisco_threat_alerts(time)
    #get data length
    data_count = 0
    if results is not None:
        final_results = convert_to_array(results['cached_context_objects'])
        data_count = len(final_results)

    if data_count > 0:
        logging.info("Posting data to Sentinel")
        post_status_code = post_data(json.dumps(final_results))
        logging.info(f"Post Status Code: {post_status_code}")
        if post_status_code is not None:
            logging.info("Posted {} events to Azure sentinel. Time period: from {}.".format(data_count, time[0]))
    else:
        logging.info("No events to process. Time period: from {}".format(time[0]))