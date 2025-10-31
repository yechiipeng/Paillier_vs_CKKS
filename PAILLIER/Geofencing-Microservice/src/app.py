from flask import Flask, jsonify, request
from phe import paillier
import requests
import overpass
import math
import time

app = Flask(__name__)

# Global variable to store geofence point coordinates
geofence_coordinates = []

def get_geofence_coordinates():
    global geofence_coordinates
    api = overpass.API(timeout=60000)
    query = """
    node["amenity"="cafe"](50.0,-10.0,60.0,2.0);
    out qt 10000;
    """
    try:
        result = api.get(query)
        num_coordinates = len(result['features'])
        print(f"Total lon-lat pairs: {num_coordinates}")
        count = 0
        numGeofenceBoundaries = 10
        if num_coordinates < numGeofenceBoundaries:
            raise ValueError(f"Insufficient coordinates: Found {num_coordinates}, but need at least {numGeofenceBoundaries}")
        for feature in result['features']:
            if count >= numGeofenceBoundaries:
                break
            lon, lat = feature['geometry']['coordinates']
            lon_rounded, lat_rounded = round(lon, 6), round(lat, 6)
            print(f"longitude: {lon_rounded}, latitude: {lat_rounded}")
            geofence_coordinates.append([math.radians(lon_rounded), math.radians(lat_rounded)])
            count += 1
        print(f"Number of processed geofence coordinates: {len(geofence_coordinates)}")
        print("Geofence coordinates fetched successfully.")
    except Exception as e:
        print(f"Failed to fetch geofence coordinates: {e.__class__.__name__}: {e}")

get_geofence_coordinates()

def get_key_authority_public_key():
    try:
        response = requests.get('http://keyauthority:5002/get-public-key')
        response.raise_for_status()
        data = response.json()
        return data.get('public_key_n')
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch public key: {e}")
        return None

def extract_encrypted_location_prop(data, public_key):
    required_keys = [
        'c1_ct', 'c1_exp',
        'c2_ct', 'c2_exp',
        'c3_ct', 'c3_exp'
    ]
    missing_keys = [key for key in required_keys if key not in data['user_encrypted_location']]
    if missing_keys:
        raise ValueError(f"Missing required keys in 'user_encrypted_location': {', '.join(missing_keys)}")
    user_location_data = data['user_encrypted_location']
    c1 = paillier.EncryptedNumber(public_key, user_location_data.get('c1_ct'), user_location_data.get('c1_exp'))
    c2 = paillier.EncryptedNumber(public_key, user_location_data.get('c2_ct'), user_location_data.get('c2_exp'))
    c3 = paillier.EncryptedNumber(public_key, user_location_data.get('c3_ct'), user_location_data.get('c3_exp'))
    print("c1:", c1)
    print("c2:", c2)
    print("c3:", c3)
    return (c1, c2, c3)

def calculate_intermediate_haversine_value_prop(c1, c2, c3):
    start = time.time()
    haversine_intermediate_values = []
    for center_longitude, center_latitude in geofence_coordinates:
        haversine_intermediate = 1 - c1 * math.sin(center_latitude) - c2 * math.cos(center_latitude) * math.cos(center_longitude) - c3 * math.cos(center_latitude) * math.sin(center_longitude)
        haversine_intermediate_values.append(haversine_intermediate)
    end = time.time()
    print("(Runtime Performance Experiment) Computation Runtime Proposed:", round((end-start), 3), "s")
    serialized_values = []
    for intermediate_value in haversine_intermediate_values:
        ciphertext = intermediate_value.ciphertext()
        exponent = intermediate_value.exponent
        serialized_values.append({'ciphertext': ciphertext, 'exponent': exponent})
    return serialized_values

def submit_geofence_results_to_key_authority(public_key_n, intermediate_values, endpoint):
    try:
        payload = {
            "public_key_n": public_key_n,
            "encrypted_results": intermediate_values
        }
        response = requests.post(
            f"http://keyauthority:5002/{endpoint}",
            json=payload
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to post results to key authority: {e}")
        return None

@app.route("/submit-mobile-node-location-prop", methods=['POST'])
def submit_mobile_node_location_prop():
    data = request.get_json()
    if not data:
        return jsonify({
            "status": "error",
            "message": "Request data is missing"
        }), 400
    if 'user_encrypted_location' not in data or 'public_key_n' not in data:
        return jsonify({
            "status": "error",
            "message": "Missing 'user_encrypted_location' or 'public_key_n' in request data"
        }), 400
    public_key_n_current = get_key_authority_public_key()
    public_key = paillier.PaillierPublicKey(public_key_n_current)
    if data['public_key_n'] != public_key_n_current:
        return jsonify({
            "status": "error",
            "message": "Public key mismatch. Encryption was not done with the correct public key."
        }), 400
    try:
        encrypted_values = extract_encrypted_location_prop(data, public_key)
    except ValueError as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400
    intermediate_values = calculate_intermediate_haversine_value_prop(*encrypted_values)
    # Submit intermediate values to key authority and get result
    keyauth_response = submit_geofence_results_to_key_authority(public_key_n_current, intermediate_values, "submit-geofence-result-prop")
    # Return the actual result from key authority (inside/outside/unknown)
    if keyauth_response and "results" in keyauth_response:
        return jsonify({
            "status": "success",
            "results": keyauth_response["results"]
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": "Failed to get geofence decision from key authority",
            "results": keyauth_response.get("results") if keyauth_response else None
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)