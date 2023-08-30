import main
import redis
import json
import os

twitter = main.make_token()
client_id = os.environ.get("CLIENT_ID")
client_secret = os.environ.get("CLIENT_SECRET")
# client_id = CLIENT_ID
# client_secret = CLIENT_SECRET
token_url = "https://api.twitter.com/2/oauth2/token"

t = main.r.get("token")
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
main.r.set("token", j_refreshed_token)

tweets = main.get_tweets()
for tweet in tweets:
    payload = {"text": tweet}
    main.post_tweet(payload, refreshed_token)
