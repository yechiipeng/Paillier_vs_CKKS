from flask import Flask, jsonify, request
import requests
import overpass
import math
import tenseal as ts
import base64
import time

app = Flask(__name__)

# Global variable to store geofence point coordinates
geofence_coordinates = []

def get_geofence_coordinates():
    global geofence_coordinates
    print("Fetching geofence coordinates...")
    
    # Use fallback coordinates first to prevent startup delays
    geofence_coordinates = [
        [math.radians(-9.724087), math.radians(51.573037)],
        [math.radians(-9.724000), math.radians(51.573100)],
        [math.radians(-9.723900), math.radians(51.572900)],
        [math.radians(-9.723800), math.radians(51.572800)],
        [math.radians(-9.723700), math.radians(51.572700)]
    ]
    
    try:
        api = overpass.API(timeout=5)  # Reduced timeout
        query = """
        node["amenity"="cafe"](50.0,-10.0,60.0,2.0);
        out qt 100;
        """
        result = api.get(query)
        # Clear fallback and use API data if successful
        geofence_coordinates = []
        numGeofenceBoundaries = 3  # Further reduced for performance
        count = 0
        for feature in result['features']:
            if count >= numGeofenceBoundaries:
                break
            lon, lat = feature['geometry']['coordinates']
            lon_rounded, lat_rounded = round(lon, 6), round(lat, 6)
            geofence_coordinates.append([math.radians(lon_rounded), math.radians(lat_rounded)])
            count += 1
        print(f"Successfully loaded {len(geofence_coordinates)} geofence coordinates from API")
    except Exception as e:
        print(f"Failed to fetch geofence coordinates: {e}")
        print(f"Using {len(geofence_coordinates)} fallback coordinates")
        # Keep the fallback coordinates already set

get_geofence_coordinates()

def deserialize_ckks_vector(serialized_vec, context):
    return ts.ckks_vector_from(context, base64.b64decode(serialized_vec.encode("utf-8")))

@app.route("/submit-mobile-node-location-ckks", methods=['POST'])
def submit_mobile_node_location_ckks():
    try:
        data = request.get_json()
        if not data or 'user_encrypted_location' not in data or 'ckks_context' not in data:
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        context = ts.context_from(base64.b64decode(data['ckks_context'].encode("utf-8")))
        user_terms = data['user_encrypted_location']
        c1_enc = deserialize_ckks_vector(user_terms['c1_enc'], context)
        c2_enc = deserialize_ckks_vector(user_terms['c2_enc'], context)
        c3_enc = deserialize_ckks_vector(user_terms['c3_enc'], context)

        intermediate_values = []
        for idx, (center_longitude, center_latitude) in enumerate(geofence_coordinates):
            # Optimize computation - use simpler operations
            val = c1_enc * (-math.sin(center_latitude))
            val += c2_enc * (-math.cos(center_latitude) * math.cos(center_longitude))
            val += c3_enc * (-math.cos(center_latitude) * math.sin(center_longitude))
            val += 1
            intermediate_values.append(base64.b64encode(val.serialize()).decode("utf-8"))

        payload = {
            "ckks_context": data['ckks_context'],
            "intermediate_values": intermediate_values
        }
        response = requests.post(
            "http://keyauthority:5002/submit-geofence-result-prop-ckks",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        keyauth_response = response.json()
        return jsonify(keyauth_response), 200
        
    except Exception as e:
        print("Error in /submit-mobile-node-location-ckks:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)