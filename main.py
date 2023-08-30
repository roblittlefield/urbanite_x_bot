from google.cloud import secretmanager
import os
import re
import redis
from requests_oauthlib import OAuth2Session
import requests
import json
from datetime import datetime, timedelta


def get_calls():
    sf_data_url = 'https://data.sfgov.org/resource/gnap-fj3t.json'
    sf_data_parameters = {
        "$limit": 5000,
    }
    response = requests.get(url=sf_data_url, params=sf_data_parameters)
    response.raise_for_status()
    data_sf = response.json()
    print(f"Number of retrieved calls {len(data_sf)}\n")
    return data_sf


def text_proper_case(text_raw):
    text = text_raw \
        .replace(r'\\\\', '\\') \
        .replace(r'0(\d)', r'\1') \
        .replace('\\', '/') \
        .split('/')[:2]

    text = '/'.join(text).lower().title().strip()[:45]
    return text


def get_tweets():
    calls = get_calls()
    call_tweets = []
    for call in calls:
        if call["call_type_final"] == str(217):  # 459 freq for testing, 217 = shooting
            received_date_string = call["received_datetime"]
            received_date = datetime.strptime(received_date_string, '%Y-%m-%dT%H:%M:%S.%f')
            received_date_pst = received_date - timedelta(hours=7)

            time_difference = datetime.now() - received_date
            total_seconds = time_difference.total_seconds()
            minutes_ago = round(total_seconds / 60, 1)
            hours_ago = round(total_seconds / 3600, 1)
            call_type_desc = call['call_type_final_desc'].title()

            if call["onscene_datetime"]:
                onscene_date_string = call["onscene_datetime"]
                onscene_date = datetime.strptime(onscene_date_string, '%Y-%m-%dT%H:%M:%S.%f')
                onscene_date_pst = onscene_date - timedelta(hours=7)

                response_time_diff = onscene_date_pst - received_date_pst
                response_time = round(response_time_diff.total_seconds() / 60)

                print(f"Time ago: {hours_ago} hours. Response time: {response_time} mins.")
                if minutes_ago < 100000:
                    new_tweet = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} at {received_date_pst.strftime('%I:%M %p')}, Priority {call['priority_final']}, SFPD Response time: {response_time}m urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                    call_tweets.append(new_tweet)
            else:
                if minutes_ago < 100000:
                    new_tweet = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} at {received_date_pst.strftime('%I:%M %p')}, Priority {call['priority_final']}, SFPD currently responding, urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                    call_tweets.append(new_tweet)

    print(f"\nNumber of shootings in last 8 hrs: {len(call_tweets)}\n")

    return call_tweets


def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


def post_tweet(payload, token):
    print("Tweeting!")
    return requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )


client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
redirect_uri = os.environ.get("REDIRECT_URI")
redis_url = os.environ.get("REDIS_URL")

r = redis.from_url(redis_url)
token_url = "https://api.twitter.com/2/oauth2/token"
auth_url = "https://twitter.com/i/oauth2/authorize"
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]


def run_bot():
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

    tweets = get_tweets()
    for tweet in tweets:
        payload = {"text": tweet}
        post_tweet(payload, refreshed_token)

run_bot()
