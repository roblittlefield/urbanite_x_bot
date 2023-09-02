from google.cloud import secretmanager
from google.cloud import storage
import functions_framework
import re
import redis
from requests_oauthlib import OAuth2Session
import requests
import json
from datetime import datetime, timedelta

# Google Cloud Storage Urbanite Twitter Bot Bucket
storage_client = storage.Client()
bucket_name = "urbanite-x-bot-data"
bucket = storage_client.bucket(bucket_name)

posted_tweets_file = "posted_tweets.csv"
posted_tweets_blob = bucket.blob(posted_tweets_file)
posted_tweets_existing_data = posted_tweets_blob.download_as_text()

tweets_wo_rt_file = "tweets_wo_rt.csv"
tweets_wo_rt_blob = bucket.blob(tweets_wo_rt_file)
tweet_wo_rt_existing_data = tweets_wo_rt_blob.download_as_text()


def text_proper_case(text_raw):
    parts = text_raw.replace('\\\\', '\\').replace('\\', '/').replace(r'0(\d)', r'\1').split('/')
    for i in range(len(parts)):
        parts[i] = ' '.join(word.capitalize() for word in parts[i].split())
    text = ' / '.join(parts).strip()[:45]
    return text


def find_tweet_id_by_cad_number(cad_number_try):
    try:
        if cad_number_try in posted_tweets_existing_data:
            lines = posted_tweets_existing_data.split('\n')
            for line in lines:
                parts = line.strip().split('-')
                if len(parts) == 2 and parts[0].strip() == cad_number_try:
                    print("Found original tweet, getting ID to reply to")
                    return parts[1].strip()
            return False  # Cad number not found
        else:
            print(f"CAD number '{cad_number_try}' not found in the content.")
            return False
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False


def get_calls():
    sf_data_url = 'https://data.sfgov.org/resource/gnap-fj3t.json'
    sf_data_parameters = {
        "$limit": 8000,
    }
    response = requests.get(url=sf_data_url, params=sf_data_parameters)
    response.raise_for_status()
    data_sf = response.json()
    print(f"Number of retrieved SFPD calls: {len(data_sf)}\n")
    return data_sf


def get_tweets(refreshed_token):
    calls = get_calls()
    call_tweets = []
    for call in calls:
        if call["call_type_final"] == str(217) or call["call_type_final"] == str(219) or call["call_type_final"] == str(212):  # 459 freq for testing, 217 = shooting
            # Break for repeat tweets
            cad_number = call["cad_number"]
            on_view = call["onview_flag"]
            if on_view == "Y":
                on_view_text = "Officer Observed, "
            else:
                on_view_text = ""
            if cad_number in posted_tweets_existing_data:
                print(f'Already posted tweet with this CAD #{cad_number}')
                continue

            received_date_string = call["received_datetime"]
            received_date = datetime.strptime(received_date_string, '%Y-%m-%dT%H:%M:%S.%f')

            if received_date.hour < 10 or (12 < received_date.hour < 22):
                hour = received_date.strftime('%l')[1]
            else:
                hour = received_date.strftime('%I')
            received_date_min = received_date.strftime(f':%M %p')
            received_date_formatted = "at " + hour + received_date_min

            time_now = datetime.now() - timedelta(hours=7)
            time_difference = time_now - received_date
            total_seconds = time_difference.total_seconds()
            minutes_ago = round(total_seconds / 60, 1)
            hours_ago = round(total_seconds / 3600, 1)

            if hours_ago > 24:
                continue

            try:
                call_type_desc = call['call_type_final_desc'].title()
            except KeyError:
                call_type_desc = call['call_type_original_desc'].title()  # correct
            print(f"{call_type_desc}: {minutes_ago} minutes ago. CAD {cad_number}")

            try:
                onscene_date_string = call["onscene_datetime"]
                onscene_date = datetime.strptime(onscene_date_string, '%Y-%m-%dT%H:%M:%S.%f')
                response_time_diff = onscene_date - received_date
                response_time = round(response_time_diff.total_seconds() / 60)
                print(f"Response time: {response_time} mins")

                tweet_wo_rt_id = find_tweet_id_by_cad_number(cad_number)
                if tweet_wo_rt_id:
                    print(f"Call tweeted already but without RT, adding RT in reply...{tweet_wo_rt_id}")
                    new_reply = f"Call answered, replying with response time: {response_time}m"
                    response = post_tweet_reply(tweet_wo_rt_id, new_reply, refreshed_token)
                    tweet_wo_rt_id = json.loads(response.text)["data"]["id"]
                    if response.status_code == 201:
                        mark_cad_posted(cad_number, tweet_wo_rt_id)
                        print(f"Posted Reply Tweet w RT CAD {cad_number} posted with ID: {tweet_wo_rt_id}")
                    elif response.status_code == 429:
                        print("ERROR 429, MAXED OUT RATE LIMIT")
                    elif response.status_code == 403:
                        response_data = response.json()
                        if 'errors' in response_data:
                            for error in response_data['errors']:
                                if 'code' in error and error['code'] == 187:
                                    mark_cad_posted(cad_number, tweet_wo_rt_id)
                                    print("Duplicate tweet detected, added to Posted Tweets. Error:", error['message'])
                    else:
                        print(F"Tweet posting failed. RESPONSE STATUS CODE {response.status_code}")
                else:
                    new_tweet = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} {received_date_formatted}, Priority {call['priority_final']}, {on_view_text}SFPD response time: {response_time}m urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                    call_tweets.append(new_tweet)
            except KeyError:
                global tweet_wo_rt_existing_data
                if cad_number in tweet_wo_rt_existing_data:
                    print(f'Already posted tweet w/o RT with this CAD #{cad_number}')
                    continue
                print("No response time yet, adding tweet as wo rt")
                new_tweet_wo = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} {received_date_formatted}, Priority {call['priority_final']}, {on_view_text}SFPD currently responding... urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                call_tweets.append(new_tweet_wo)

    print(f"Number of new stabbing/shootings/strong arm robberies: {len(call_tweets)}\n")
    return call_tweets


def mark_cad_posted(cad_number, tweet_id):
    global posted_tweets_existing_data
    posted_tweets_new_data = f"{cad_number}-{tweet_id},\n"
    posted_tweets_existing_data += posted_tweets_new_data
    posted_tweets_blob.upload_from_string(posted_tweets_existing_data)
    print(f"Added call #{cad_number} with Tweet ID: {tweet_id}")


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


def post_tweet_reply(tweet_id, tweet, token):
    payload = {"text": tweet}
    print("Trying to reply to an earlier Tweet!")
    return requests.request(
        "POST",
        f"https://api.twitter.com/2/tweets/{tweet_id}/reply",
        json=payload,
        headers={
            "Authorization": f"Bearer {token['access_token']}",
            "Content-Type": "application/json",
        },
    )


client = secretmanager.SecretManagerServiceClient()
client_id = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_ID/versions/latest"}).payload.data.decode("UTF-8")
client_secret = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/CLIENT_SECRET/versions/latest"}).payload.data.decode("UTF-8")
redirect_uri = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIRECT_URI/versions/latest"}).payload.data.decode("UTF-8")
redis_url = client.access_secret_version(request={"name": "projects/urbanite-x-bot/secrets/REDIS_URL/versions/latest"}).payload.data.decode("UTF-8")

r = redis.from_url(redis_url)
token_url = "https://api.twitter.com/2/oauth2/token"
auth_url = "https://twitter.com/i/oauth2/authorize"
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]


@functions_framework.cloud_event
def run_bot(cloud_event):
    twitter = make_token()
    t = r.get("token")
    bb_t = t.decode("utf8").replace("'", '"')
    data = json.loads(bb_t)

    refreshed_token = twitter.refresh_token(
        client_id=client_id,
        client_secret=client_secret,
        token_url=token_url,
        refresh_token=data["refresh_token"],
    )

    st_refreshed_token = '"{}"'.format(refreshed_token)
    j_refreshed_token = json.loads(st_refreshed_token)
    r.set("token", j_refreshed_token)

    tweets = get_tweets(refreshed_token)
    for tweet in tweets:
        payload = {"text": tweet}
        response = post_tweet(payload, refreshed_token)

        if response.status_code == 201:
            tweet_id = json.loads(response.text)["data"]["id"]
            cad_number = payload["text"][-9:]

            contains_response_time = "SFPD response time:" in tweet
            if not contains_response_time:
                global tweet_wo_rt_existing_data
                tweets_wo_rt_new_data = f"{cad_number}-{tweet_id},\n"
                tweet_wo_rt_existing_data += tweets_wo_rt_new_data
                tweets_wo_rt_blob.upload_from_string(tweet_wo_rt_existing_data)
                print(f"Tweet without RT, CAD {cad_number} posted with ID: {tweet_id}")
            else:
                mark_cad_posted(cad_number, tweet_id)
                print(f"Tweeted w RT, CAD {cad_number} posted with ID: {tweet_id}")
        else:
            print(f"Tweet posting failed. Error {response.status_code}")
