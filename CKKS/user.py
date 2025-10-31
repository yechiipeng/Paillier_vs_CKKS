import tenseal as ts
import requests
import math
import time
import threading
import csv
import sys
import base64
import json
from metrics_logger import log_metrics, get_cpu_ram, get_ckks_ciphertext_size, compute_classification_metrics

# Global variable to store CKKS context
ckks_context_serialized = None

def get_key_authority_ckks_context():
    global ckks_context_serialized
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.get('http://localhost:5002/get-ckks-context', timeout=15)
            response.raise_for_status()
            data = response.json()
            ckks_context_serialized = data.get('ckks_context')
            context = ts.context_from(base64.b64decode(ckks_context_serialized.encode("utf-8")))
            print(f"Successfully connected to KeyAuthority (attempt {attempt + 1})")
            return context
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed to fetch CKKS context: {e}")
            if attempt < max_retries - 1:
                time.sleep(2)  # Wait before retry
    return None

def compute_and_encrypt_user_location_terms_ckks(user_latitude, user_longitude, context):
    start = time.time()
    c1 = ts.ckks_vector(context, [math.sin(user_latitude)])
    c2 = ts.ckks_vector(context, [math.cos(user_latitude) * math.cos(user_longitude)])
    c3 = ts.ckks_vector(context, [math.cos(user_latitude) * math.sin(user_longitude)])
    end = time.time()
    print("(CKKS) Encryption Runtime:", round((end-start), 3), "s")
    return (c1, c2, c3)

def serialize_ckks_vector(vec):
    return base64.b64encode(vec.serialize()).decode("utf-8")

def is_inside_geofence_plaintext(user_latitude, user_longitude, geofence_center_lat, geofence_center_lon, radius_m):
    R = 6371000  # Earth radius in meters
    dlat = user_latitude - geofence_center_lat
    dlon = user_longitude - geofence_center_lon
    a = math.sin(dlat/2)**2 + math.cos(user_latitude) * math.cos(geofence_center_lat) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    distance = R * c
    return "inside" if distance < radius_m else "outside"

def send_encrypted_location_to_geofencing_service_ckks(c1, c2, c3, request_id, plaintext_decision):
    t_start = time.time()
    cpu_start, ram_start = get_cpu_ram()
    encryption_start = time.time()
    ciphertexts = [c1, c2, c3]
    ciphertext_size = sum(get_ckks_ciphertext_size(serialize_ckks_vector(c)) for c in ciphertexts)
    encryption_end = time.time()
    
    try:
        payload = {
            "user_encrypted_location": {
                "c1_enc": serialize_ckks_vector(c1),
                "c2_enc": serialize_ckks_vector(c2),
                "c3_enc": serialize_ckks_vector(c3)
            },
            "ckks_context": ckks_context_serialized
        }
        
        response = requests.post(
            'http://localhost:5001/submit-mobile-node-location-ckks',
            json=payload,
            timeout=30
        )
        payload_size = len(json.dumps(payload))
        response.raise_for_status()
        result = response.json()
        
        encrypted_decision = "unknown"
        if "results" in result and len(result["results"]) > 0:
            encrypted_decision = result["results"][0]["status"]
        elif "status" in result:
            encrypted_decision = result["status"]
            
    except Exception as e:
        print(f"Failed to post CKKS results to geofencing service: {e}")
        encrypted_decision = "error"
        payload_size = 0
    
    decryption_start = time.time()
    decryption_end = time.time()
    cpu_end, ram_end = get_cpu_ram()
    t_end = time.time()
    
    log_metrics(
        "1000_results_ckks.csv",
        [
            "scheme", "request_id", "correct", "plaintext_decision", "encrypted_decision",
            "encryption_time", "decryption_time", "total_time", "cpu_start", "cpu_end", "ram_start", "ram_end",
            "ciphertext_size", "payload_size"
        ],
        {
            "scheme": "CKKS-proposed",
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

def scalability_experiment_ckks(user_location_terms_ckks, num_requests):
    geofence_center_lat = math.radians(51.573037)
    geofence_center_lon = math.radians(-9.724087)
    radius_m = 1000  # 1 km

    user_latitude = math.radians(round(51.573037, 5))
    user_longitude = math.radians(round(-9.724087, 5))
    plaintext_decision = is_inside_geofence_plaintext(user_latitude, user_longitude, geofence_center_lat, geofence_center_lon, radius_m)

    start_time = time.time()
    y_true = []
    y_pred = []
    
    # Use sequential processing for better reliability and less system load
    successful_requests = 0
    for i in range(num_requests):
        try:
            decision = send_encrypted_location_to_geofencing_service_ckks(
                *user_location_terms_ckks, i, plaintext_decision
            )
            if decision and decision != "error":
                y_pred.append(decision)
                y_true.append(plaintext_decision)
                successful_requests += 1
            time.sleep(0.1)  # Small delay to prevent overload
        except Exception as e:
            print(f"Request {i} failed: {e}")
            continue
    
    end_time = time.time()
    total_runtime = end_time - start_time
    
    if successful_requests > 0:
        throughput = successful_requests / total_runtime
        latency = total_runtime / successful_requests
        
        print(f"System runtime for {successful_requests}/{num_requests} successful requests: {round(total_runtime, 3)} s")
        print(f"Throughput: {round(throughput, 3)} queries/second")
        print(f"Latency: {round(latency, 3)} seconds/query")
        print(f"Success rate: {(successful_requests/num_requests)*100:.1f}%")

        if len(y_true) > 0 and len(y_pred) > 0:
            acc, prec, rec, f1 = compute_classification_metrics(y_true, y_pred)
            print(f"(CKKS-proposed) Accuracy: {acc:.3f}, Precision: {prec:.3f}, Recall: {rec:.3f}, F1: {f1:.3f}")
        else:
            acc = prec = rec = f1 = 0.0
            print("(CKKS-proposed) No successful predictions to evaluate")

        with open("1000_results_ckks.csv", "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["CKKS-optimized", round(total_runtime, 3), round(throughput, 3), round(latency, 3), 
                           acc, prec, rec, f1, successful_requests, num_requests])
    else:
        print(f"All {num_requests} requests failed!")

def main():
    context = get_key_authority_ckks_context()
    if context is None:
        print("CKKS context not available. Make sure KeyAuthority is running!")
        return
        
    user_latitude, user_longitude = math.radians(round(51.573037, 5)), math.radians(round(-9.724087, 5))
    user_location_terms_ckks = compute_and_encrypt_user_location_terms_ckks(user_latitude, user_longitude, context)

    # Run only 1000 requests per experiment for reduced load
    num_requests = 1000
    print(f"\n--- CKKS Scalability Experiment: {num_requests} requests ---")
    scalability_experiment_ckks(user_location_terms_ckks, num_requests=num_requests)

if __name__ == "__main__":
    # Run 1000 requests 30 times forS scalability analysis
    for run in range(30):
        print(f"\n=== CKKS Experiment Run {run+1}/30 ===")
        main()
        time.sleep(1)  # Small delay between runs to prevent system overload