from google.cloud import secretmanager
from google.cloud import storage
import functions_framework
import re
import redis
from redis.exceptions import ConnectionError
from requests_oauthlib import OAuth2Session
import requests
import json
from datetime import datetime, timedelta

client = secretmanager.SecretManagerServiceClient()
client_id = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_ID_ALAMO/versions/latest"}).payload.data.decode("UTF-8")
client_secret = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_SECRET_ALAMO/versions/latest"}).payload.data.decode("UTF-8")
redirect_uri = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIRECT_URI_ALAMO/versions/latest"}).payload.data.decode("UTF-8")
redis_url = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIS_URL_ALAMO/versions/latest"}).payload.data.decode("UTF-8")

token_url = "https://api.twitter.com/2/oauth2/token"
auth_url = "https://twitter.com/i/oauth2/authorize"
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]

posted_tweets_existing_data = None

storage_client = storage.Client()
bucket = storage_client.bucket("urbanite-x-bot-data")

posted_tweets_file = "posted_tweets_break_ins.json"
posted_tweets_blob = bucket.blob(posted_tweets_file)
posted_tweets_existing_data = posted_tweets_blob.download_as_text()
try:
    posted_tweets_existing_data = json.loads(posted_tweets_existing_data)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON: {e}")


def text_proper_case(text_raw):
    parts = text_raw.replace('\\\\', '\\').replace('\\', '/').replace(r'0(\d)', r'\1').split('/')
    for i in range(len(parts)):
        parts[i] = ' '.join(word.capitalize() for word in parts[i].split())
    text = ' / '.join(parts).strip()[:45]
    if text[0] == "0":
        text = text[1:]
    return text


def get_calls():
    sf_data_url = 'https://data.sfgov.org/resource/gnap-fj3t.json'
    sf_data_parameters = {
        "$limit": 6000,
    }
    response = requests.get(url=sf_data_url, params=sf_data_parameters)
    response.raise_for_status()
    data_sf = response.json()
    call_count = len(data_sf)
    return data_sf, call_count


def get_police_disposition_text(code):
    disposition_ref = {
        "ABA": "officer abated",
        "ADM": "officer admonished",
        "ADV": "officer advised",
        "ARR": "arrest made",
        "CAN": "call cancelled",
        "CSA": "CPSA assignment",
        "CIT": "citation issued",
        "CRM": "burglary alarm",
        "GOA": "gone on arrival",
        "HAN": "officer handled",
        "NCR": "no issue found",
        "ND": "related to another call",
        "NOM": "no merit",
        "PAS": "home alarm",
        "REP": "police report made",
        "SFD": "EMS engaged",
        "UTL": "unable to locate",
        "VAS": "car alarm",
    }
    return disposition_ref.get(code)


def get_neighborhood(neighborhood_raw):
    neighborhood_formatted = {
        "Financial District/South Beach": "Financial",
        "Lone Mountain/USF": "USF",
        "Castro/Upper Market": "Castro",
        "Sunset/Parkside": "Sunset",
        "West of Twin Peaks": "W Twin Peaks",
        "Bayview Hunters Point": "Bayview",
        "Oceanview/Merced/Ingleside": "OMI",
        "South of Market": "SoMa",
    }
    return neighborhood_formatted.get(neighborhood_raw)


def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def post_tweet(new_tweet, token):
    payload = {
        "text": new_tweet
    }
    # print("Sending Tweet with payload:", payload)
    url = "https://api.twitter.com/2/tweets"
    headers = {
        "Authorization": "Bearer {}".format(token["access_token"]),
        "Content-Type": "application/json",
    }
    response = requests.post(url, json=payload, headers=headers)
    # print("Response Status Code:", response.status_code)
    return response


@functions_framework.cloud_event
def run_bot(cloud_event):
    global posted_tweets_existing_data
    already_posted = 0
    new_tweets_count = 0

    twitter = make_token()
    try:
        r = redis.from_url(redis_url)
    except ConnectionError as e:
        print(f"Error connecting to Redis: {e}")
        r = None
        raise e
    t = r.get("token")

    bb_t = t.decode("utf8").replace("'", '"')
    try:
        data = json.loads(bb_t)
    except json.JSONDecodeError as e:
        print(f"Error decoding token: {e}")
        return

    try:
        refreshed_token = twitter.refresh_token(
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            refresh_token=data["refresh_token"],
        )
    except Exception as e:
        print(f"Error refreshing token: {e}")
        return

    st_refreshed_token = '"{}"'.format(refreshed_token)
    j_refreshed_token = json.loads(st_refreshed_token)
    r.set("token", j_refreshed_token)

    # Get Calls & Create Tweets
    calls, call_count = get_calls()
    for call in calls:
        # Clear variables
        new_tweet = ""

        # Call type filter
        included_call_types = ["851", "852"]  # 851 stolen car, 852 car break-in
        if call["call_type_final"] in included_call_types:

            # Redundancy filters
            cad_number = call["cad_number"]
            if cad_number in posted_tweets_existing_data:
                # print(f"{cad_number} already in posted data")
                already_posted += 1
                continue

            # Data Processing
            on_view = call["onview_flag"]
            on_view_text = ""
            if on_view == "Y":
                on_view_text = ", officer observed"
            try:
                received_date_string = call["received_datetime"]
            except KeyError:
                continue
            received_date = datetime.strptime(received_date_string, '%Y-%m-%dT%H:%M:%S.%f')

            time_now = datetime.now() - timedelta(hours=7)
            time_difference = time_now - received_date
            total_seconds = time_difference.total_seconds()
            hours_ago = round(total_seconds / 3600, 1)
            if hours_ago > 12:
                continue
            minutes_ago = round(total_seconds / 60, 1)
            hour = received_date.strftime('%I').lstrip('0')

            received_date_min = received_date.strftime(f':%M %p')
            received_date_formatted = "at " + hour + received_date_min
            try:
                disposition_code = call['disposition']
                disposition = f", {get_police_disposition_text(disposition_code)}"
            except KeyError:
                disposition = ""

            if call["call_type_final"] == "852":
                call_type_desc = "Car break-in / strip"
            elif call["call_type_final"] == "851":
                call_type_desc = "Stolen vehicle"

            # print(f"{call_type_desc}: {minutes_ago} minutes ago. CAD {cad_number}")

            try:
                neighborhood = get_neighborhood(call['analysis_neighborhood'])
                if not neighborhood:
                    neighborhood = call['analysis_neighborhood']
            except KeyError:
                continue

            try:
                onscene_date_string = call["onscene_datetime"]
                onscene_date = datetime.strptime(onscene_date_string, '%Y-%m-%dT%H:%M:%S.%f')
                response_time_diff = onscene_date - received_date
                response_time = round(response_time_diff.total_seconds() / 60)
                response_time_str = ""
                if not on_view == "Y":
                    response_time_str = f", SFPD response time: {response_time}m"
            except KeyError:
                response_time_str = ""

            # Creating Tweet or reply
            if not disposition == ", no merit":
                new_tweet = f"{neighborhood.upper()}: {call_type_desc} near {text_proper_case(call['intersection_name'])} {received_date_formatted}, Priority {call['priority_final']}{on_view_text}{response_time_str}{disposition} urbanitesf.netlify.app/?cad={call['cad_number'] }"
                response = post_tweet(new_tweet, refreshed_token)
                if response is None:
                    continue
                elif response.status_code == 201:
                    tweet_id = json.loads(response.text)["data"]["id"]
                elif response.status_code == 403:
                    tweet_id = 403
                elif response.status_code == 429:
                    break
                else:
                    break
            else:
                new_tweet = ""
                tweet_id = 100

            # Add to GCF Bucket Blob
            posted_tweets_existing_data[cad_number] = tweet_id
            new_tweets_count += 1

    # New Tweets
    if new_tweets_count > 0:
        posted_tweets_new_data = json.dumps(posted_tweets_existing_data)
        posted_tweets_blob.upload_from_string(posted_tweets_new_data)

    print(f"Bips: {new_tweets_count} + {already_posted} / {call_count} calls")
    return "Ok"
