from phe import paillier
import requests
import math
import time
import threading
import csv
import sys
from metrics_logger import log_metrics, get_cpu_ram, get_ciphertext_size, compute_classification_metrics

# Global variable to store paillier public key
public_key_n = None

def get_key_authority_public_key():
    global public_key_n
    try:
        response = requests.get('http://localhost:5002/get-public-key')
        response.raise_for_status()
        data = response.json()
        public_key_n = data.get('public_key_n')
        public_key = paillier.PaillierPublicKey(public_key_n)
        return public_key
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch public key: {e}")
        return None

def compute_and_encrypt_user_location_terms(user_latitude, user_longitude, public_key):
    start = time.time()
    c1 = public_key.encrypt(math.sin(user_latitude))
    c2 = public_key.encrypt(math.cos(user_latitude) * math.cos(user_longitude))
    c3 = public_key.encrypt(math.cos(user_latitude) * math.sin(user_longitude))
    end = time.time()
    print("(Runtime Performance Experiment) Encryption Runtime:", round((end-start), 3), "s")
    print("c1_enc:", c1)
    print("c2_enc:", c2)
    print("c3_enc:", c3)
    return (c1, c2, c3)

def is_inside_geofence_plaintext(user_latitude, user_longitude, geofence_center_lat, geofence_center_lon, radius_m):
    R = 6371000  # Earth radius in meters
    dlat = user_latitude - geofence_center_lat
    dlon = user_longitude - geofence_center_lon
    a = math.sin(dlat/2)**2 + math.cos(user_latitude) * math.cos(geofence_center_lat) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    distance = R * c
    return "inside" if distance < radius_m else "outside"

def send_encrypted_location_to_geofencing_service(c1, c2, c3, request_id, plaintext_decision):
    t_start = time.time()
    cpu_start, ram_start = get_cpu_ram()
    encryption_start = time.time()
    ciphertexts = [c1, c2, c3]
    ciphertext_size = sum(get_ciphertext_size(c) for c in ciphertexts)
    encryption_end = time.time()
    try:
        c1_ct = c1.ciphertext()
        c1_exp = c1.exponent
        c2_ct = c2.ciphertext()
        c2_exp = c2.exponent
        c3_ct = c3.ciphertext()
        c3_exp = c3.exponent
        payload = {
            "user_encrypted_location": {
                "c1_ct": c1_ct, "c1_exp": c1_exp, 
                "c2_ct": c2_ct, "c2_exp": c2_exp,
                "c3_ct": c3_ct, "c3_exp": c3_exp
            },
            "public_key_n": public_key_n,
        }
        import json
        response = requests.post(
            'http://localhost:5001/submit-mobile-node-location-prop',
            json=payload
        )
        payload_size = len(json.dumps(payload))
        response.raise_for_status()
        result = response.json()
        encrypted_decision = None
        if "results" in result:
            encrypted_decision = result["results"][0]["status"]
        else:
            encrypted_decision = "unknown"
    except Exception as e:
        print(f"Failed to post results to key authority: {e}")
        encrypted_decision = "error"
        payload_size = 0
    decryption_start = time.time()
    decryption_end = time.time()
    cpu_end, ram_end = get_cpu_ram()
    t_end = time.time()
    log_metrics(
        "1000_requests_results.csv",
        [
            "scheme", "request_id", "correct", "plaintext_decision", "encrypted_decision",
            "encryption_time", "decryption_time", "total_time", "cpu_start", "cpu_end", "ram_start", "ram_end",
            "ciphertext_size", "payload_size"
        ],
        {
            "scheme": "Paillier-baseline",
            "request_id": request_id,
            "correct": plaintext_decision == encrypted_decision,
            "plaintext_decision": plaintext_decision,
            "encrypted_decision": encrypted_decision,
            "encryption_time": encryption_end - encryption_start,
            "decryption_time": decryption_end - decryption_start,
            "total_time": t_end - t_start,
            "cpu_start": cpu_start,
            "cpu_end": cpu_end,
            "ram_start": ram_start,
            "ram_end": ram_end,
            "ciphertext_size": ciphertext_size,
            "payload_size": payload_size
        }
    )
    return encrypted_decision

def scalability_experiment(user_location_terms, num_requests):
    geofence_center_lat = math.radians(51.573037)
    geofence_center_lon = math.radians(-9.724087)
    radius_m = 1000  # 1 km

    user_latitude = math.radians(round(51.573037, 5))
    user_longitude = math.radians(round(-9.724087, 5))
    plaintext_decision = is_inside_geofence_plaintext(user_latitude, user_longitude, geofence_center_lat, geofence_center_lon, radius_m)

    start_time = time.time()
    threads = []
    y_true = []
    y_pred = []
    for i in range(num_requests):
        thread = threading.Thread(
            target=lambda idx: y_pred.append(
                send_encrypted_location_to_geofencing_service(
                    *user_location_terms, idx, plaintext_decision
                )
            ),
            args=(i,)
        )
        threads.append(thread)
        thread.start()
        y_true.append(plaintext_decision)
    for thread in threads:
        thread.join()
    end_time = time.time()

    print("Ground truth:", y_true)
    print("Predictions:", y_pred)

    total_runtime = end_time - start_time
    throughput = num_requests / total_runtime
    latency = total_runtime / num_requests

    print(f"System runtime for {num_requests} requests excluding encryption runtime: {round(total_runtime, 3)} s")
    print(f"Throughput: {round(throughput, 3)} queries/second")
    print(f"Latency: {round(latency, 3)} seconds/query")

    acc, prec, rec, f1 = compute_classification_metrics(y_true, y_pred)
    print(f"(Paillier-baseline) Accuracy: {acc:.3f}, Precision: {prec:.3f}, Recall: {rec:.3f}, F1: {f1:.3f}")

    with open("1000_requests_results.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["System", "Runtime (s)", "Throughput (q/s)", "Latency (s/q)", "Accuracy", "Precision", "Recall", "F1"])
        writer.writerow(["Paillier-baseline", round(total_runtime, 3), round(throughput, 3), round(latency, 3), acc, prec, rec, f1])

def main():
    public_key = get_key_authority_public_key()
    user_latitude, user_longitude = math.radians(round(51.573037, 5)), math.radians(round(-9.724087, 5))
    user_location_terms = compute_and_encrypt_user_location_terms(user_latitude, user_longitude, public_key)
    scalability_experiment(user_location_terms, num_requests=1000)

if __name__ == "__main__":
    for run in range(30):
        print(f"--- Experiment Run {run+1} ---")
        main()