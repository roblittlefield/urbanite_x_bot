from google.cloud import secretmanager
import functions_framework
import re
import redis
from requests_oauthlib import OAuth2Session
import requests
import json
from datetime import datetime, timedelta


def get_calls():
    print("Getting calls...")
    sf_data_url = 'https://data.sfgov.org/resource/gnap-fj3t.json'
    sf_data_parameters = {
        "$limit": 8000,
    }
    response = requests.get(url=sf_data_url, params=sf_data_parameters)
    response.raise_for_status()
    data_sf = response.json()
    print(f"Number of retrieved SFPD calls (unfiltered): {len(data_sf)}\n")
    return data_sf


def text_proper_case(text_raw):
    text = text_raw \
        .replace(r'\\\\', '\\') \
        .replace(r'0(\d)', r'\1') \
        .replace('\\', '/') \
        .split('/')[:2]

    text = '/'.join(text).lower().title().strip()[:45]
    return text


def find_tweet_id_by_cad_number(cad_number_try):
    try:
        with open("posted_tweets.txt", 'r') as file:
            lines = file.readlines()
            for line in lines:
                parts = line.strip().split('-')
                if len(parts) == 2 and parts[0].strip() == cad_number_try:
                    return parts[1].strip()
            return None  # Cad number not found
    except FileNotFoundError:
        print(f"The file 'posted_tweets' was not found.")
        return None


def get_tweets(refreshed_token):
    calls = get_calls()
    call_tweets = []

    for call in calls:

        if call["call_type_final"] == str(217) or call["call_type_final"] == str(219):  # 459 freq for testing, 217 = shooting

            cad_number = call["cad_number"]
            with open("posted_tweets.txt", "r") as file:
                tweets = file.read()
                if cad_number in tweets:
                    continue

            received_date_string = call["received_datetime"]
            received_date = datetime.strptime(received_date_string, '%Y-%m-%dT%H:%M:%S.%f')
            received_date_pst = received_date - timedelta(hours=7)

            time_difference = datetime.now() - received_date
            total_seconds = time_difference.total_seconds()
            minutes_ago = round(total_seconds / 60, 1)
            hours_ago = round(total_seconds / 3600, 1)
            call_type_desc = call['call_type_final_desc'].title()

            if call["onscene_datetime"]:
                tweet_id = find_tweet_id_by_cad_number(cad_number)

                onscene_date_string = call["onscene_datetime"]
                onscene_date = datetime.strptime(onscene_date_string, '%Y-%m-%dT%H:%M:%S.%f')
                onscene_date_pst = onscene_date - timedelta(hours=7)

                response_time_diff = onscene_date_pst - received_date_pst
                response_time = round(response_time_diff.total_seconds() / 60)

                print(f"Time ago: {hours_ago} hours. Response time: {response_time} mins. CAD {cad_number}")
                if minutes_ago < 60:
                    if tweet_id:
                        new_reply = f"SFPD Priority {call['priority_final']}, Response time: {response_time}m"
                        response = post_tweet_reply(tweet_id, new_reply, refreshed_token)
                        if response.status_code == 201:
                            tweet_id = json.loads(response.text)["data"]["id"]
                            with open("posted_tweets.txt", "a") as file:
                                file.write(f"{cad_number}-{tweet_id}\n")
                            print(f"Posted Reply Tweet w RT CAD {cad_number} posted with ID: {tweet_id}")
                        else:
                            print("Tweet posting failed.")
                    else:
                        new_tweet = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} at {received_date_pst.strftime('%I:%M %p')}, Priority {call['priority_final']}, SFPD Response time: {response_time}m urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                        call_tweets.append(new_tweet)
            else:
                if minutes_ago < 60:
                    print(f"Time ago: {hours_ago} hours. No response time yet. CAD {cad_number}")
                    new_tweet = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} at {received_date_pst.strftime('%I:%M %p')}, Priority {call['priority_final']}, SFPD currently responding urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                    call_tweets.append(new_tweet)

    print(f"Number of new shootings in last 60 minutes: {len(call_tweets)}\n")

    return call_tweets


def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def post_tweet(payload, token):
    print("Trying to Tweet!")
    payload["geo"] = {
        "coordinates": [-122.4194, 37.7749],
        "type": "Point"
    }
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
    payload = {
        "text": tweet,
        "geo": {
            "coordinates": [-122.4194, 37.7749],
            "type": "Point"
        }
    }
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
client_id = client.access_secret_version(request={"name": "projects/urbanite-sf-twitter-bot/secrets/CLIENT_ID/versions/latest"}).payload.data.decode("UTF-8")
client_secret = client.access_secret_version(request={"name": "projects/urbanite-sf-twitter-bot/secrets/CLIENT_SECRET/versions/latest"}).payload.data.decode("UTF-8")
redirect_uri = client.access_secret_version(request={"name": "projects/urbanite-sf-twitter-bot/secrets/REDIRECT_URI/versions/latest"}).payload.data.decode("UTF-8")
redis_url = client.access_secret_version(request={"name": "projects/urbanite-sf-twitter-bot/secrets/REDIS_URL/versions/latest"}).payload.data.decode("UTF-8")

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

            contains_response_time = "Response Time:" in tweet
            if not contains_response_time:
                with open("tweets_without_rt.txt", "a") as file:
                    file.write(f"{cad_number}-{tweet_id}\n")
                print(f"Tweet w/o RT CAD {cad_number} posted with ID: {tweet_id}")
            else:
                with open("posted_tweets.txt", "a") as file:
                    file.write(f"{cad_number}-{tweet_id}\n")
                print(f"Tweet w RT CAD {cad_number} posted with ID: {tweet_id}")
        else:
            print("Tweet posting failed.")
