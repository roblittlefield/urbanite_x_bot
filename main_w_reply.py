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

tweets_awaiting_disposition_existing_data = None
storage_client = storage.Client()
bucket_name = "urbanite-x-bot-data"
bucket = storage_client.bucket(bucket_name)

posted_tweets_file = "posted_tweets.csv"
posted_tweets_blob = bucket.blob(posted_tweets_file)
posted_tweets_existing_data = posted_tweets_blob.download_as_text()

tweets_awaiting_rt_file = "tweets_awaiting_rt.csv"
tweets_awaiting_rt_blob = bucket.blob(tweets_awaiting_rt_file)
tweets_awaiting_rt_existing_data = tweets_awaiting_rt_blob.download_as_text()

tweets_awaiting_disposition_file = "tweets_awaiting_disposition.csv"
tweets_awaiting_disposition_blob = bucket.blob(tweets_awaiting_disposition_file)
tweets_awaiting_disposition_existing_data = tweets_awaiting_disposition_blob.download_as_text()


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


def find_tweet_id_by_cad_number(cad_number_try, blob):
    try:
        lines = blob.split('\n')
        for line in lines:
            parts = line.strip().split('-')
            if len(parts) == 2 and parts[0].strip() == cad_number_try:
                tweet_id = parts[1].strip()
                print(f"trying to reply to {tweet_id}")
                return tweet_id
        return None
    except FileNotFoundError:
        print(f"The blob {blob} for {cad_number_try} was not found in bucket.")
        return None


def get_tweets(refreshed_token):
    global posted_tweets_existing_data
    global tweets_awaiting_disposition_existing_data
    global tweets_awaiting_rt_existing_data
    global already_posted
    global replies
    calls = get_calls()
    call_tweets = []
    for call in calls:
        included_call_types = ["217", "219"]  # shooting, stabbing REMOVED: "212" sa robbery, "603" prowler, "646" stalking
        if call["call_type_final"] in included_call_types:
            cad_number = call["cad_number"]
            if cad_number in posted_tweets_existing_data:
                print("already in posted files")
                already_posted += 1
                continue

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
            if hours_ago > 30:
                continue
            minutes_ago = round(total_seconds / 60, 1)
            hour = received_date.strftime('%I').lstrip('0')

            received_date_min = received_date.strftime(f':%M %p')
            received_date_formatted = "at " + hour + received_date_min
            print('CAD <50 hrs & not fully posted, proceeding...')
            try:
                disposition_code = call['disposition']
                disposition = f", {get_police_disposition_text(disposition_code)}"
                if disposition == ", no merit":
                    continue
            except KeyError:
                disposition = ""

            try:
                call_type_desc = call['call_type_final_desc'].title()
            except KeyError:
                call_type_desc = call['call_type_original_desc'].title()
            print(f"{call_type_desc}: {minutes_ago} minutes ago. CAD {cad_number}")

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

            tweet_id = find_tweet_id_by_cad_number(cad_number, tweets_awaiting_rt_existing_data)
            if tweet_id:
                print("Previous tweet w/o RT or disposition (or both) found")
                if response_time_str != "":
                    print("New RT and/or disp found, trying to tweet reply")
                    tweet_wo_disp_id = find_tweet_id_by_cad_number(cad_number, tweets_awaiting_disposition_existing_data)
                    if disposition == "":
                        if tweet_wo_disp_id:
                            continue
                        replies += 1
                        reply_rt_tweet = f"{response_time_str[2:]}"
                        try:
                            response = post_reply(tweet_id, reply_rt_tweet, refreshed_token)
                        except ValueError as e:
                            print(f"Error: {e}")
                        if response.status_code == 201:
                            new_reply_rt_id = json.loads(response.text)["data"]["id"]

                            tweets_awaiting_disposition_new_data = f"{cad_number}-{new_reply_rt_id}\n"
                            tweets_awaiting_disposition_existing_data += tweets_awaiting_disposition_new_data
                            tweets_awaiting_disposition_blob.upload_from_string(tweets_awaiting_disposition_existing_data)
                            print(f"Tweet without disposition, CAD {cad_number} posted with ID: {tweet_id}")
                        else:
                            print(f"REPLY tweet w/o disposition posting failed. RESPONSE STATUS CODE {response.status_code}")
                            continue
                    else:
                        replies += 1
                        # tweet_wo_disp_id = find_tweet_id_by_cad_number(cad_number, tweets_awaiting_disposition_existing_data)
                        if tweet_wo_disp_id:
                            reply_tweet = f"Outcome: {disposition[2:]}"
                            print("Already had RT, replying with just disposition")
                        else:
                            reply_tweet = f"{response_time_str[2:]}{disposition}"
                            print("Trying to reply with RT and disposition")
                        response = post_reply(tweet_wo_disp_id, reply_tweet, refreshed_token)
                        print("Tweeted reply with disposition and RT")
                        if response.status_code == 201:
                            new_reply_disp_id = json.loads(response.text)["data"]["id"]
                            mark_cad_posted(cad_number, new_reply_disp_id)
                            print(f"Replied to CAD {cad_number}, posted with ID: {new_reply_disp_id}")
                        else:
                            print(f"REPLY tweet with disposition posting failed. RESPONSE STATUS CODE {response.status_code}")
                            continue

            else:
                # new_tweet = f"{neighborhood.upper()}: {call_type_desc} near {text_proper_case(call['intersection_name'])} {received_date_formatted}, Priority {call['priority_final']}{on_view_text}{response_time_str}{disposition} urbanitesf.netlify.app/?cad={call['cad_number'] }"
                new_tweet = f"{call_type_desc} in {neighborhood.upper()} near {text_proper_case(call['intersection_name'])} {received_date_formatted}, Priority {call['priority_final']}{on_view_text}{response_time_str}{disposition} #SanFrancisco urbanitesf.netlify.app/?cad={call['cad_number'] }"
                call_tweets.append(new_tweet)

    return call_tweets


def mark_cad_posted(cad_number, tweet_id):
    global posted_tweets_existing_data
    posted_tweets_new_data = f"{cad_number}-{tweet_id}\n"
    posted_tweets_existing_data += posted_tweets_new_data
    posted_tweets_blob.upload_from_string(posted_tweets_existing_data)
    print(f"Added call #{cad_number} with Tweet ID: {tweet_id}")
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


def post_reply(tweet_id, tweet, token):
    if tweet_id is None:
        raise ValueError("tweet_id is None, cannot post reply")
    print('Post Reply fn called')
    payload = {
        "text": tweet,
        "reply": {
            "in_reply_to_tweet_id": tweet_id
        }
    }
    url = "https://api.twitter.com/2/tweets"

    headers = {
        "Authorization": "Bearer {}".format(token["access_token"]),
        "Content-Type": "application/json",
    }

    print("Sending POST request to:", url)
    print("Request Headers:", headers)
    print("Request Body:", json.dumps(payload))

    response = requests.post(url, json=payload, headers=headers)

    print("Response Status Code:", response.status_code)
    print("Response Headers:", response.headers)
    print("Response Content:", response.text)

    return response


client = secretmanager.SecretManagerServiceClient()
client_id = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_ID/versions/latest"}).payload.data.decode("UTF-8")
client_secret = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_SECRET/versions/latest"}).payload.data.decode("UTF-8")
redirect_uri = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIRECT_URI/versions/latest"}).payload.data.decode("UTF-8")
redis_url = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIS_URL/versions/latest"}).payload.data.decode("UTF-8")

try:
    r = redis.from_url(redis_url)
except ConnectionError as e:
    print(f"Error connecting to Redis: {e}")
    r = None
    raise e
token_url = "https://api.twitter.com/2/oauth2/token"
auth_url = "https://twitter.com/i/oauth2/authorize"
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]


@functions_framework.cloud_event
def run_bot(cloud_event):
    global already_posted
    global call_count
    global replies
    global tweets_awaiting_rt_existing_data
    already_posted = 0
    call_count = 0
    replies = 0
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

    tweets = get_tweets(refreshed_token)
    for tweet in tweets:
        payload = {
            "text": tweet
        }
        response = post_tweet(payload, refreshed_token)
        cad_number = payload["text"][-9:]

        if response.status_code == 201:
            tweet_id = json.loads(response.text)["data"]["id"]
            contains_response_time = "SFPD response time" in tweet
            if not contains_response_time:
                tweet_awaiting_rt_new_data = f"{cad_number}-{tweet_id}\n"
                tweets_awaiting_rt_existing_data += tweet_awaiting_rt_new_data
                tweets_awaiting_rt_blob.upload_from_string(tweets_awaiting_rt_existing_data)
                print(f"Tweet without RT, CAD {cad_number} posted with ID: {tweet_id}")
            else:
                mark_cad_posted(cad_number, tweet_id)
                print(f"Tweeted w RT, CAD {cad_number} posted with ID: {tweet_id}")
        elif response.status_code == 429:
            print(f"ERROR {response.status_code}, MAXED OUT RATE LIMIT")
        elif response.status_code == 403:
            response_data = response.json()
            if 'errors' in response_data:
                for error in response_data['errors']:
                    if 'code' in error and error['code'] == 187:
                        mark_cad_posted(cad_number, "duplicate tweet")
                        print("Duplicate tweet detected, added to Posted Tweets. Error:", error['message'])
        else:
            print(f"Tweet posting failed. RESPONSE STATUS CODE {response.status_code}")

    print(f"Retrieved priority A incident calls: {call_count}, already tweeted: {already_posted}, new tweets: {len(tweets)}, new replies: {replies}.")
    return 'OK'
