from google.cloud import secretmanager
from google.cloud import storage
import functions_framework
import re
import redis
from requests_oauthlib import OAuth2Session
import requests
import json
from datetime import datetime, timedelta

posted_tweets_existing_data = None
storage_client = storage.Client()
bucket_name = "urbanite-x-bot-data"
bucket = storage_client.bucket(bucket_name)

posted_tweets_file = "posted_tweets_break_ins.csv"
posted_tweets_blob = bucket.blob(posted_tweets_file)
posted_tweets_existing_data = posted_tweets_blob.download_as_text()


def text_proper_case(text_raw):
    parts = text_raw.replace('\\\\', '\\').replace('\\', '/').replace(r'0(\d)', r'\1').split('/')
    for i in range(len(parts)):
        parts[i] = ' '.join(word.capitalize() for word in parts[i].split())
    text = ' / '.join(parts).strip()[:45]
    if text[0] == "0":
        text = text[1:]
    return text


def get_calls():
    global call_count
    sf_data_url = 'https://data.sfgov.org/resource/gnap-fj3t.json'
    sf_data_parameters = {
        "$limit": 6000,
    }
    response = requests.get(url=sf_data_url, params=sf_data_parameters)
    response.raise_for_status()
    data_sf = response.json()
    call_count = len(data_sf)
    return data_sf


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


def get_tweets():
    global posted_tweets_existing_data
    global already_posted
    calls = get_calls()
    call_tweets = []
    for call in calls:
        if call["call_type_final"] == str(851) or call["call_type_final"] == str(852):  # 851 stolen car, 852 car break-in
            cad_number = call["cad_number"]
            if cad_number in posted_tweets_existing_data:
                # print(f'Break-in/GTA Posted Already CAD #{cad_number}')
                already_posted += 1
                continue

            if call["call_type_final"] == str(851):
                call_desc = "Stolen vehicle"
            elif call["call_type_final"] == str(852):
                call_desc = "Car break-in"

            on_view = call["onview_flag"]
            if on_view == "Y":
                on_view_text = ", officer observed"
            else:
                on_view_text = ""

            received_date_string = call["received_datetime"]
            received_date = datetime.strptime(received_date_string, '%Y-%m-%dT%H:%M:%S.%f')

            time_now = datetime.now() - timedelta(hours=7)
            time_difference = time_now - received_date
            total_seconds = time_difference.total_seconds()
            hours_ago = round(total_seconds / 3600, 1)
            if hours_ago > 6:
                continue
            minutes_ago = round(total_seconds / 60, 1)
            hour = received_date.strftime('%I').lstrip('0')
            print(f"{call_desc}: {minutes_ago} minutes ago. CAD {cad_number}")

            received_date_min = received_date.strftime(f':%M %p')
            received_date_formatted = "at " + hour + received_date_min

            try:
                disposition_code = call['disposition']
                disposition = f", {get_police_disposition_text(disposition_code)}"
                if disposition == "No merit":
                    continue
            except KeyError:
                disposition = ""
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
                if not on_view == "Y":
                    response_time_str = f", SFPD response time: {response_time}m"
                else:
                    response_time_str = ""
            except KeyError:
                response_time_str = ""

            new_tweet = f"{neighborhood.upper()}: {call_desc} near {text_proper_case(call['intersection_name'])} {received_date_formatted}, Priority {call['priority_final']}{on_view_text}{response_time_str}{disposition} urbanitesf.netlify.app/?cad={call['cad_number']}"  # https://data.sfgov.org/resource/gnap-fj3t.json?cad_number={call['cad_number']}
            call_tweets.append(new_tweet)

    return call_tweets


def mark_cad_posted(cad_number, tweet_id):
    global posted_tweets_existing_data
    posted_tweets_new_data = f"{cad_number}-{tweet_id}\n"
    try:
        posted_tweets_existing_data += posted_tweets_new_data
        posted_tweets_blob.upload_from_string(posted_tweets_existing_data)
        print(f"Added call #{cad_number} with Tweet ID: {tweet_id}")
    except Exception as e:
        print(f"Error adding call #{cad_number} with Tweet ID: {tweet_id}")
        print(f"Error details: {str(e)}")
    return ''

def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def post_tweet(payload, token):
    print("Trying to Tweet!")
    return requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )


client = secretmanager.SecretManagerServiceClient()
client_id = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_ID_ALAMO/versions/latest"}).payload.data.decode("UTF-8")
client_secret = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_SECRET_ALAMO/versions/latest"}).payload.data.decode("UTF-8")
redirect_uri = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIRECT_URI_ALAMO/versions/latest"}).payload.data.decode("UTF-8")
redis_url = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIS_URL_ALAMO/versions/latest"}).payload.data.decode("UTF-8")

r = redis.from_url(redis_url)
token_url = "https://api.twitter.com/2/oauth2/token"
auth_url = "https://twitter.com/i/oauth2/authorize"
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]


@functions_framework.cloud_event
def run_bot(cloud_event):
    global already_posted
    global call_count
    already_posted = 0
    call_count = 0
    twitter = make_token()
    t = r.get("token")

    if r is None:
        print("No token round on Redis...exiting")
        return

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

    tweets = get_tweets()
    for tweet in tweets:
        payload = {
            "text": tweet
        }
        response = post_tweet(payload, refreshed_token)
        cad_number = payload["text"][-9:]

        if response.status_code == 201:
            tweet_id = json.loads(response.text)["data"]["id"]
            mark_cad_posted(cad_number, tweet_id)
            print(f"Tweeted breakin/GTA CAD {cad_number} posted with ID: {tweet_id}")
        elif response.status_code == 429:
            print(f"BREAKIN ERROR {response.status_code}, MAXED OUT RATE LIMIT")
        elif response.status_code == 403:
            response_data = response.json()
            if 'errors' in response_data:
                for error in response_data['errors']:
                    if 'code' in error and error['code'] == 187:
                        mark_cad_posted(cad_number, "duplicate tweet")
                        print("Duplicate tweet detected, added to Posted Tweets. Error:", error['message'])
        else:
            print(F"Tweet posting failed. RESPONSE STATUS CODE {response.status_code}")

    print(f"Retrieved car break-in/stolen car calls: {call_count}, already tweeted: {already_posted}, new tweets: {len(tweets)}.")
    return 'OK'
