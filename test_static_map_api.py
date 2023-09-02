import requests

google_maps_api = "https://maps.googleapis.com/maps/api/staticmap?"
google_maps_key = "AIzaSyDj1XYW-k5zY7kBTJfdpm-Qw_ZoPwP7ZPE"
google_maps_signature = "0-fSaya8-o3vNXtcn0yIlEB__60="
google_map_parameters = {
    "center": "37.7749,-122.4194",
    "zoom": 15,
    "size": "500x500",
    "key": google_maps_key,
    "signature": google_maps_signature,
}


response = requests.get(url=google_maps_api, params=google_map_parameters)
if response.status_code == 200:
    with open("map_image.png", "wb") as f:
        f.write(response.content)
        print("Map image saved as map_image.png")
else:
    print("Failed to retrieve the map image. Status code:", response.status_code)
