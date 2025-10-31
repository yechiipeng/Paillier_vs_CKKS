from flask import Flask, jsonify, request
from phe import paillier
import math
import time

app = Flask(__name__)

# Generate Paillier public and private keys
public_key, private_key = paillier.generate_paillier_keypair()
radius = 100            # Geofence radius in meters
earth_radius = 6371000  # Approximate Earth radius in meters

@app.route("/get-public-key", methods=['GET'])
def get_public_key():
    public_key_data = {
        "public_key_n": public_key.n
    }
    return jsonify(public_key_data)

def parse_encrypted_results(encrypted_results, public_key):
    encrypted_result_list = []
    try:
        for entry in encrypted_results:
            ciphertext_value = entry.get("ciphertext")
            exponent = entry.get("exponent")
            if ciphertext_value is None or exponent is None:
                raise ValueError("Missing ciphertext or exponent in encrypted result entry")
            encrypted_result = paillier.EncryptedNumber(public_key, ciphertext_value, exponent)
            encrypted_result_list.append(encrypted_result)
            print("encrypted result:", encrypted_result)
        return encrypted_result_list
    except Exception as e:
        print(f"Error parsing encrypted results: {e}")
        return None

def decrypt_encrypted_results(encrypted_result_list, private_key):
    decrypted_values = []
    try:
        for encrypted_result in encrypted_result_list:
            decrypted_value = private_key.decrypt(encrypted_result)
            decrypted_values.append(decrypted_value)
        return decrypted_values
    except Exception as e:
        print(f"Error decrypting encrypted results: {e}")
        return None

def evaluate_geofence_result_prop(haversine_intermediate_values):
    results = []
    for haversine_intermediate in haversine_intermediate_values:
        try:
            distance = 2 * earth_radius * math.asin(math.sqrt(haversine_intermediate / 2))
            print(f"Distance from geofence centre: {round(distance, 2)} meters")
            results.append(1 if distance <= radius else 0)
        except Exception as e:
            print(f"Unexpected error in evaluate_geofence_result: {e}")
            return None
    return results

@app.route("/submit-geofence-result-prop", methods=['POST'])
def submit_geofence_result_prop():
    data = request.get_json()
    if not data or 'encrypted_results' not in data or 'public_key_n' not in data:
        return jsonify({
            "status": "error",
            "message": "Missing 'encrypted_results' or 'public_key_n' in request data"
        }), 400
    if data['public_key_n'] != public_key.n:
        return jsonify({
            "status": "error",
            "message": "Public key mismatch. Encryption was not done with the correct public key."
        }), 400
    encrypted_result_list = parse_encrypted_results(data['encrypted_results'], public_key)
    if encrypted_result_list is None:
        return jsonify({
            "status": "error",
            "message": "Invalid encrypted results"
        }), 400
    start_prop = time.time()
    haversine_intermediate_values = decrypt_encrypted_results(encrypted_result_list, private_key)
    if haversine_intermediate_values is None:
        return jsonify({
            "status": "error",
            "message": "Couldn't decrypt encrypted results",
        }), 500
    results = evaluate_geofence_result_prop(haversine_intermediate_values)
    end_prop = time.time()
    print("(Runtime Performance Experiment) Decryption & Evaluation Runtime Proposed:", round((end_prop-start_prop), 3), "s")
    # Return a list of results for each geofence
    status_list = [{"status": "inside" if r == 1 else "outside"} for r in results]
    return jsonify({
        "status": "success",
        "results": status_list
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5002)