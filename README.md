# Urbanite SF Twitter Bot

Live Link: https://twitter.com/SFPDcallsBot SFPD calls Bot

## Application Description

Urbanite SF Twitter Bot is a Google Cloud Function Python script that pulls San Francisco law enforcement dispatched calls for service data from the city and tweets serious incidents. 

## Features

- Near Real-time Data Updates: Bot ensures up-to-date information by refreshing SFPD data every 5 minutes.
- Comprehensive Data Processing: The system meticulously processes data, incorporating vital details such as response time, as well as the conclusion and disposition of each incident.
- Links to Map: Includes link to Urbanite SF website with more data on the call, including location on the map

## Components

Urbanite SF was crafted using Python and deployed on Google Cloud Functions, leveraging the Twitter (X) OAuth 2.0 API for seamless integration.

## Future Work

- Open to ideas!

## Code

### Running Bot

Using run_bot as an entry point, the function pulls data and posts tweets for relevant, new calls. 

```python
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
                tweets_wo_rt_new_data = f"{cad_number}-{tweet_id}\n"
                tweet_wo_rt_existing_data += tweets_wo_rt_new_data
                tweets_wo_rt_blob.upload_from_string(tweet_wo_rt_existing_data)
                print(f"Tweet without RT, CAD {cad_number} posted with ID: {tweet_id}")
            else:
                mark_cad_posted(cad_number, tweet_id)
                print(f"Tweeted w RT, CAD {cad_number} posted with ID: {tweet_id}")
        else:
            print(f"Tweet posting failed. Error {response.status_code}")
```

### Accessing Data SF Dataset to Get Calls

The app then calls the DataSF Real-Time Law Enforcement Dispatched Calls for Service API using a filter.

```python
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
```

### Compose Tweet Text from the Calls

the get_tweets() function creates a detailed tweet message based on as much available data there is for a new call, and if SFPD have not responded yet, it will mark the tweet for a later reply with SFPD response times and call conclusions. 

```python
def get_tweets(refreshed_token):
    calls = get_calls()
    call_tweets = []
    for call in calls:
        if call["call_type_final"] == str(217) or call["call_type_final"] == str(219) or call["call_type_final"] == str(212):  # 459 freq for testing, 217 = shooting
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
                disposition_code = call['disposition']
                disposition = f", {get_police_disposition_text(disposition_code)}"

            except KeyError:
                disposition = ""

            try:
                onscene_date_string = call["onscene_datetime"]
                onscene_date = datetime.strptime(onscene_date_string, '%Y-%m-%dT%H:%M:%S.%f')
                response_time_diff = onscene_date - received_date
                response_time = round(response_time_diff.total_seconds() / 60)
                print(f"Response time: {response_time} mins")

                tweet_wo_rt_id = find_tweet_id_by_cad_number(cad_number)
                if tweet_wo_rt_id:
                    print(f"Call tweeted already but without RT, adding RT in reply...{tweet_wo_rt_id}")
                    new_reply = f"SFPD on-scene, response time: {response_time}m{disposition}"
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
                    new_tweet = f"{call_type_desc} at {text_proper_case(call['intersection_name'])} in {call['analysis_neighborhood']} {received_date_formatted}, Priority {call['priority_final']}, {on_view_text}SFPD response time: {response_time}m{disposition} urbanitesf.netlify.app/?cad_number={call['cad_number'] }"
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
```

### Avoiding Duplicates

To avoid duplicate Twitter API POSTs, details for each tweet are saved in a Google Cloud Bucket storage container. 

```python
# Accessing the storage bucket
storage_client = storage.Client()
bucket_name = "urbanite-x-bot-data"
bucket = storage_client.bucket(bucket_name)

posted_tweets_file = "posted_tweets.csv"
posted_tweets_blob = bucket.blob(posted_tweets_file)
posted_tweets_existing_data = posted_tweets_blob.download_as_text()

tweets_wo_rt_file = "tweets_wo_rt.csv"
tweets_wo_rt_blob = bucket.blob(tweets_wo_rt_file)
tweet_wo_rt_existing_data = tweets_wo_rt_blob.download_as_text()

# Saving Data to the bucket CSV files
def mark_cad_posted(cad_number, tweet_id):
    global posted_tweets_existing_data
    posted_tweets_new_data = f"{cad_number}-{tweet_id}\n"
    posted_tweets_existing_data += posted_tweets_new_data
    posted_tweets_blob.upload_from_string(posted_tweets_existing_data)
    print(f"Added call #{cad_number} with Tweet ID: {tweet_id}")
```

### Posting Tweet

The bot uses Twitter's API to post

```python
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
```
