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
client_id = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_ID/versions/latest"}).payload.data.decode("UTF-8")
client_secret = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_SECRET/versions/latest"}).payload.data.decode("UTF-8")
redirect_uri = 'http://127.0.0.1:5000/oauth/callback'
redis_url = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIS_URL/versions/latest"}).payload.data.decode("UTF-8")

token_url = "https://api.twitter.com/2/oauth2/token"
auth_url = "https://twitter.com/i/oauth2/authorize"
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]

posted_tweets_existing_data = {}
tweets_awaiting_rt_existing_data = {}
tweets_awaiting_disposition_existing_data = {}

storage_client = storage.Client()
bucket = storage_client.bucket("urbanite-x-bot-data")

posted_tweets_file = "posted_tweets.json"
posted_tweets_blob = bucket.blob(posted_tweets_file)
posted_tweets_blob.cache_control = "no-store, max-age=0"
posted_tweets_existing_data = posted_tweets_blob.download_as_text()
try:
    posted_tweets_existing_data = json.loads(posted_tweets_existing_data)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON: {e}")

tweets_awaiting_rt_file = "tweets_awaiting_rt.json"
tweets_awaiting_rt_blob = bucket.blob(tweets_awaiting_rt_file)
tweets_awaiting_rt_blob.cache_control = "no-store, max-age=0"
tweets_awaiting_rt_existing_data = tweets_awaiting_rt_blob.download_as_text()
try:
    tweets_awaiting_rt_existing_data = json.loads(tweets_awaiting_rt_existing_data)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON: {e}")

tweets_awaiting_disposition_file = "tweets_awaiting_disposition.json"
tweets_awaiting_disposition_blob = bucket.blob(tweets_awaiting_disposition_file)
tweets_awaiting_disposition_blob.cache_control = "no-store, max-age=0"
tweets_awaiting_disposition_existing_data = tweets_awaiting_disposition_blob.download_as_text()
try:
    tweets_awaiting_disposition_existing_data = json.loads(tweets_awaiting_disposition_existing_data)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON: {e}")


def text_proper_case(text_raw):
    text_raw = text_raw.replace('\\\\', '\\')
    text_raw = text_raw.replace('\\', '/')
    text_raw = re.sub(r'0(\d)', r'\1', text_raw)
    parts = text_raw.split('/')

    for i in range(len(parts)):
        parts[i] = ' '.join(word.capitalize() for word in parts[i].split())
        if parts[i][0] == "0":
            parts[i] = parts[i][1:]
        parts[i] = parts[i].replace("Mcc", "McC")
    text = ' / '.join(parts).strip()[:45]
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


def find_tweet_id_by_cad_number(cad_number_try, data_dict):
    try:
        tweet_id = data_dict[cad_number_try]
        print(f"Found previous tweet: {tweet_id} for {cad_number_try}")
        return tweet_id
    except KeyError:
        print(f"No previous tweet found for {cad_number_try}")
        print(f"Looked for previous tweet in data_dict: {data_dict}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def post_tweet(new_tweet, token, tweet_id=None):
    try:
        payload = {"text": new_tweet}

        if tweet_id is not None:
            payload["reply"] = {"in_reply_to_tweet_id": tweet_id}

        print("Sending Tweet with payload:", payload)

        url = "https://api.twitter.com/2/tweets"
        headers = {
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print("Response Status Code:", response.status_code)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error making the request: {e}")
        return response


@functions_framework.cloud_event
def run_bot(cloud_event):
    global posted_tweets_existing_data
    global tweets_awaiting_disposition_existing_data
    global tweets_awaiting_rt_existing_data
    already_posted = 0
    new_tweets_count = 0
    new_disp_replies_count = 0
    new_rt_replies_count = 0

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
        tweet_replying_to_id = None
        tweet_type = None

        # Call type filter
        included_call_types = ["217", "219", "212", "222", "221"]  # shooting, stabbing, sa robbery,  "222" person w knife, "221" person w gun, REMOVED: "216" shots fired,   "213" purse snatched, "211S" silent hold-up alarm, "152" drunk driver "211" robbery "528" fire, "646" stalking, "603" prowler, "245" agg assault,
        if call["call_type_final"] in included_call_types:

            # Redundancy filters
            cad_number = call["cad_number"]
            if cad_number in posted_tweets_existing_data:
                already_posted += 1
                continue
            if cad_number in tweets_awaiting_rt_existing_data:
                try:
                    call["onscene_datetime"]
                except KeyError:
                    continue
            if cad_number in tweets_awaiting_disposition_existing_data:
                try:
                    call["disposition"]
                except KeyError:
                    continue

            # Data Processing
            try:
                received_date_string = call["received_datetime"]
            except KeyError:
                continue
            received_date = datetime.strptime(received_date_string, '%Y-%m-%dT%H:%M:%S.%f')

            time_now = datetime.now() - timedelta(hours=7)
            time_difference = time_now - received_date
            total_seconds = time_difference.total_seconds()
            hours_ago = round(total_seconds / 3600, 1)
            if hours_ago > 24:
                continue
            # minutes_ago = round(total_seconds / 60, 1)
            hour = received_date.strftime('%I').lstrip('0')

            received_date_min = received_date.strftime(f':%M %p')
            received_date_formatted = "at " + hour + received_date_min
            try:
                disposition_code = call['disposition']
                disposition = f", {get_police_disposition_text(disposition_code)}"
            except KeyError:
                disposition = ""

            if call['call_type_final_desc'] == "PERSON W/KNIFE":
                call_type_desc = "Person with knife"
            elif call['call_type_final_desc'] == "PERSON W/GUN":
                call_type_desc = "Person with gun"
            else:
                try:
                    call_type_desc = call['call_type_final_desc'].capitalize()
                except KeyError:
                    call_type_desc = call['call_type_original_desc'].capitalize()

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
                if call["onview_flag"] == "Y":
                    response_time_str = f", officer observed"
                else:
                    response_time_str = f", SFPD response time: {response_time}m"

            except KeyError:
                response_time_str = ""

            # Creating Tweet or reply
            tweet_await_rt_id = find_tweet_id_by_cad_number(cad_number, tweets_awaiting_rt_existing_data)
            tweet_await_disp_id = find_tweet_id_by_cad_number(cad_number, tweets_awaiting_disposition_existing_data)
            if not tweet_await_rt_id and not tweet_await_disp_id:
                if not disposition == ", no merit":
                    new_tweet = f"{neighborhood.upper()}: {call_type_desc} near {text_proper_case(call['intersection_name'])} {received_date_formatted}, Priority {call['priority_final']}{response_time_str}{disposition} urbanitesf.netlify.app/?cad={call['cad_number'] }"
                    tweet_replying_to_id = None
                    if not response_time_str == "":
                        if not disposition == "":
                            tweet_type = 3
                        else:
                            tweet_type = 2
                    else:
                        tweet_type = 1
                else:
                    new_tweet = None
                    tweet_replying_to_id = None
                    tweet_type = 0
            else:
                if not tweet_await_disp_id:
                    if not disposition == "":
                        new_tweet = f"{response_time_str[2:]}{disposition}"
                        tweet_replying_to_id = tweet_await_rt_id
                        tweet_type = 3
                    else:
                        new_tweet = f"{response_time_str[2:]}"
                        tweet_replying_to_id = tweet_await_rt_id
                        tweet_type = 2
                else:
                    if disposition[2:] == "related to another call":
                        new_tweet = None
                        tweet_type = 0
                    else:
                        new_tweet = f"Outcome: {disposition[2:]}"
                        tweet_replying_to_id = tweet_await_disp_id
                        tweet_type = 3

            if not tweet_type == 0:
                if tweet_replying_to_id == 403:
                    continue
                response = post_tweet(new_tweet, refreshed_token, tweet_replying_to_id)
                if response is None:
                    print("Tweet Response = none")
                    continue
                elif response.status_code == 201:
                    tweet_id = json.loads(response.text)["data"]["id"]
                elif response.status_code == 403:
                    tweet_id = 403
                elif response.status_code == 429:
                    return
                else:
                    break
            else:
                tweet_id = 100

            # Add to GCF Bucket Blob
            if tweet_type == 3 or tweet_type == 0:
                posted_tweets_existing_data[cad_number] = tweet_id
                new_tweets_count += 1

            elif tweet_type == 2:
                tweets_awaiting_disposition_existing_data[cad_number] = tweet_id
                new_disp_replies_count += 1

            elif tweet_type == 1:
                tweets_awaiting_rt_existing_data[cad_number] = tweet_id
                new_rt_replies_count += 1

            print(f"Added call {cad_number} with Tweet ID {tweet_id} & type {tweet_type}")

    # New Tweets
    if new_tweets_count > 0:
        # print(f"Experimental: posted tweets based on what is still in data {posted_tweets_new}")
        # keys_to_keep = list(posted_tweets_existing_data.keys())[-min(80, len(posted_tweets_existing_data)):]
        # posted_tweets_existing_data_filtered = {key: posted_tweets_existing_data[key] for key in keys_to_keep}
        # print(f"Posted tweets existing data filtered {posted_tweets_existing_data_filtered}")
        # print(f"Posted tweets existing data {posted_tweets_existing_data}")
        # posted_tweets_new_data = json.dumps(posted_tweets_existing_data_filtered)
        posted_tweets_new_data = json.dumps(posted_tweets_existing_data)
        try:
            posted_tweets_blob.upload_from_string(posted_tweets_new_data)
        except Exception as e:
            print(f"Error uploading to posted tweets blob: {e}")

    # New Disp replies
    if new_disp_replies_count > 0:
        # print(tweets_awaiting_disposition_existing_data)
        # keys_to_keep = list(tweets_awaiting_disposition_existing_data.keys())[-min(30, len(tweets_awaiting_disposition_existing_data)):]
        # tweets_awaiting_disposition_existing_data_filtered = {key: tweets_awaiting_disposition_existing_data[key] for key in keys_to_keep}
        # print(tweets_awaiting_disposition_existing_data_filtered)
        tweets_awaiting_disposition_new_data = json.dumps(tweets_awaiting_disposition_existing_data)
        try:
            tweets_awaiting_disposition_blob.upload_from_string(tweets_awaiting_disposition_new_data)
        except Exception as e:
            print(f"Error uploading to tweets_awaiting_disp_blob: {e}")

    # New RT replies
    if new_rt_replies_count > 0:
        # print(tweets_awaiting_rt_existing_data)
        # keys_to_keep = list(tweets_awaiting_rt_existing_data.keys())[-min(30, len(tweets_awaiting_rt_existing_data)):]
        # tweets_awaiting_rt_existing_data_filtered = {key: tweets_awaiting_rt_existing_data[key] for key in keys_to_keep}
        # print(tweets_awaiting_rt_existing_data_filtered)
        print(tweets_awaiting_rt_existing_data)
        tweets_awaiting_rt_new_data = json.dumps(tweets_awaiting_rt_existing_data)
        try:
            tweets_awaiting_rt_blob.upload_from_string(tweets_awaiting_rt_new_data)
            print("Uploaded to tweets_awaiting_rt_blob.")
        except Exception as e:
             print(f"Error uploading to tweets_awaiting_rt_blob: {e}")
             print(f"Type of exception: {type(e)}")
             print(f"Additional error information: {str(e)}")
        try:
            downloaded_data = tweets_awaiting_rt_blob.download_as_text()
            print("Downloaded data:")
            print(downloaded_data)
        except Exception as e:
            print(f"Error downloading data from tweets_awaiting_rt_blob: {e}")
            print(f"Type of exception: {type(e)}")
            print(f"Additional error information: {str(e)}")

    print(f"Sevr: {new_tweets_count}, {new_disp_replies_count}, {new_rt_replies_count} + {already_posted} / {call_count} calls")
    return "Ok"
