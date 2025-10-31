from flask import Flask, jsonify, request
import tenseal as ts
import base64
import traceback

app = Flask(__name__)
# Reduced max request size for better performance
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# Generate CKKS context at startup - optimized for performance
def create_ckks_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=4096,  # Reduced from 8192
        coeff_mod_bit_sizes=[40, 21, 40]  # Simplified from [60, 40, 40, 60]
    )
    context.generate_galois_keys()
    context.global_scale = 2**21  # Reduced from 2**40
    return context

ckks_context = create_ckks_context()
ckks_context_serialized = ckks_context.serialize().decode("ISO-8859-1")

@app.route("/get-ckks-context", methods=["GET"])
def get_ckks_context():
    import base64
    return jsonify({"ckks_context": base64.b64encode(ckks_context.serialize()).decode("utf-8")})

def deserialize_ckks_vector(serialized_vec, context):
    return ts.ckks_vector_from(context, base64.b64decode(serialized_vec.encode("utf-8")))

@app.route("/submit-geofence-result-ref-ckks", methods=["POST"])
def submit_geofence_result_ref_ckks():
    data = request.get_json()
    if not data or "ckks_context" not in data or "intermediate_values" not in data:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    try:
        # Use the startup context with secret key for decryption
        context = ckks_context
        results = []
        for enc_val in data["intermediate_values"]:
            vec = deserialize_ckks_vector(enc_val, context)
            decrypted = vec.decrypt()[0]
            status = "inside" if decrypted < 0.5 else "outside"
            results.append({"value": decrypted, "status": status})
        return jsonify({"status": "success", "results": results}), 200
    except Exception as e:
        print("Error in /submit-geofence-result-ref-ckks:", e)
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/submit-geofence-result-prop-ckks", methods=["POST"])
def submit_geofence_result_prop_ckks():
    data = request.get_json()
    if not data or "ckks_context" not in data or "intermediate_values" not in data:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    try:
        # Use the startup context with secret key for decryption (more efficient)
        context = ckks_context
        results = []
        for enc_val in data["intermediate_values"]:
            vec = deserialize_ckks_vector(enc_val, context)
            decrypted = vec.decrypt()[0]
            status = "inside" if decrypted < 0.5 else "outside"
            results.append({"value": decrypted, "status": status})
        return jsonify({"status": "success", "results": results}), 200
    except Exception as e:
        print("Error in /submit-geofence-result-prop-ckks:", e)
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)