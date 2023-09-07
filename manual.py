from google.cloud import secretmanager
import base64
import hashlib
import os
import re
import redis
from requests.auth import AuthBase, HTTPBasicAuth
from requests_oauthlib import OAuth2Session, TokenUpdated
from flask import Flask, request, redirect, session, url_for, render_template
import requests
import json
from datetime import datetime, timedelta
import os

# Setting up Redis
redis_url = "rediss://red-cjsbqllm702s73fmn0c0:vPafpv9fkNnxXRuyb2HqB1pw7U05aWSD@oregon-redis.render.com:6379"
r = redis.from_url(redis_url)


# Set a variable for app to initialize it
app = Flask(__name__)
app.secret_key = os.urandom(50)

# Twitter OAuth 2.0
client_id = "NzFLTEozQkpBMHUwQnlMSU5YVWk6MTpjaQ"
client_secret = "vxpriS9s8XAusW2jWpj0KSYtb60DFt9u3-PrDt6UT2JJMoTxeg"
redirect_uri = 'http://127.0.0.1:5000/oauth/callback'
auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"

scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]

code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")


def make_token():
    return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)


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
                if minutes_ago < 10:
                    tweet = f"{call_type_desc} at {call['intersection_name'].title()} in {call['analysis_neighborhood']} at {received_date_pst.strftime('%I:%M %p')}, Priority {call['priority_final']}, SFPD Response time: {response_time}m urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                    call_tweets.append(tweet)
            else:
                if minutes_ago < 10:
                    tweet = f"{call_type_desc} at {call['intersection_name'].title()} in {call['analysis_neighborhood']} at {received_date_pst.strftime('%I:%M %p')}, Priority {call['priority_final']}, SFPD currently responding, urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
                    call_tweets.append(tweet)

    print(f"\nNumber of shootings in last 8 hrs: {len(call_tweets)}\n")

    return call_tweets


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


@app.route("/")
def demo():
    global twitter
    twitter = make_token()
    authorization_url, state = twitter.authorization_url(
        auth_url, code_challenge=code_challenge, code_challenge_method="S256"
    )
    session["oauth_state"] = state
    return redirect(authorization_url)


@app.route("/oauth/callback", methods=["GET"])
def callback():
    code = request.args.get("code")
    token = twitter.fetch_token(
        token_url=token_url,
        client_secret=client_secret,
        code_verifier=code_verifier,
        code=code,
    )
    st_token = '"{}"'.format(token)
    j_token = json.loads(st_token)
    r.set("token", j_token)
    tweets = get_tweets()
    print(tweets)
    responses = []
    for tweet in tweets:
        print(f"Tweeting: {tweet}")
        payload = {"text": tweet}
        response = post_tweet(payload, token).json()
        responses.append(response)
    return responses


if __name__ == "__main__":
    app.run()
