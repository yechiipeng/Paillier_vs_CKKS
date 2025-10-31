import pytest
import json
import tenseal as ts
import base64
from unittest.mock import patch
from src.app_ckks import app


# Create a CKKS context for testing
def create_test_ckks_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=4096,
        coeff_mod_bit_sizes=[40, 21, 21, 40]
    )
    context.generate_galois_keys()
    context.global_scale = 2**21
    return context

# Helper to serialize CKKS vector
def serialize_ckks_vector(vec):
    return base64.b64encode(vec.serialize()).decode("utf-8")

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

@patch("app_ckks.get_geofence_coordinates")
def test_submit_mobile_node_location_ref_ckks_success(mock_geo, client):
    context = create_test_ckks_context()
    # Encrypt dummy values
    alpha_sq_enc = ts.ckks_vector(context, [1.0])
    gamma_sq_enc = ts.ckks_vector(context, [2.0])
    alpha_gamma_product_A_enc = ts.ckks_vector(context, [3.0])
    zeta_theta_sq_product_A_enc = ts.ckks_vector(context, [4.0])
    zeta_theta_mu_product_A_enc = ts.ckks_vector(context, [5.0])
    zeta_mu_sq_product_A_enc = ts.ckks_vector(context, [6.0])

    data = {
        "user_encrypted_location": {
            "alpha_sq_enc": serialize_ckks_vector(alpha_sq_enc),
            "gamma_sq_enc": serialize_ckks_vector(gamma_sq_enc),
            "alpha_gamma_product_A_enc": serialize_ckks_vector(alpha_gamma_product_A_enc),
            "zeta_theta_sq_product_A_enc": serialize_ckks_vector(zeta_theta_sq_product_A_enc),
            "zeta_theta_mu_product_A_enc": serialize_ckks_vector(zeta_theta_mu_product_A_enc),
            "zeta_mu_sq_product_A_enc": serialize_ckks_vector(zeta_mu_sq_product_A_enc)
        },
        "ckks_context": context.serialize().decode("ISO-8859-1")
    }

    response = client.post(
        "/submit-mobile-node-location-ref-ckks",
        data=json.dumps(data),
        content_type="application/json"
    )
    assert response.status_code == 200
    response_json = response.get_json()
    assert response_json["status"] == "success"

@patch("app_ckks.get_geofence_coordinates")
def test_submit_mobile_node_location_ref_ckks_missing_data(mock_geo, client):
    response = client.post(
        "/submit-mobile-node-location-ref-ckks",
        data=json.dumps({}),
        content_type="application/json"
    )
    assert response.status_code == 400
    response_json = response.get_json()
    assert response_json["status"] == "error"

@patch("app_ckks.get_geofence_coordinates")
def test_submit_mobile_node_location_ref_ckks_missing_fields(mock_geo, client):
    context = create_test_ckks_context()
    data = {
        "ckks_context": context.serialize().decode("ISO-8859-1")
    }
    response = client.post(
        "/submit-mobile-node-location-ref-ckks",
        data=json.dumps(data),
        content_type="application/json"
    )
    assert response.status_code == 400
    response_json = response.get_json()
    assert response_json["status"] == "error"

@patch("app_ckks.get_geofence_coordinates")
def test_submit_mobile_node_location_prop_ckks_success(mock_geo, client):
    context = create_test_ckks_context()
    c1_enc = ts.ckks_vector(context, [1.0])
    c2_enc = ts.ckks_vector(context, [2.0])
    c3_enc = ts.ckks_vector(context, [3.0])

    data = {
        "user_encrypted_location": {
            "c1_enc": serialize_ckks_vector(c1_enc),
            "c2_enc": serialize_ckks_vector(c2_enc),
            "c3_enc": serialize_ckks_vector(c3_enc)
        },
        "ckks_context": context.serialize().decode("ISO-8859-1")
    }

    response = client.post(
        "/submit-mobile-node-location-prop-ckks",
        data=json.dumps(data),
        content_type="application/json"
    )
    assert response.status_code == 200
    response_json = response.get_json()
    assert response_json["status"] == "success"

@patch("app_ckks.get_geofence_coordinates")
def test_submit_mobile_node_location_prop_ckks_missing_data(mock_geo, client):
    response = client.post(
        "/submit-mobile-node-location-prop-ckks",
        data=json.dumps({}),
        content_type="application/json"
    )
    assert response.status_code == 400
    response_json = response.get_json()
    assert response_json["status"] == "error"

@patch("app_ckks.get_geofence_coordinates")
def test_submit_mobile_node_location_prop_ckks_missing_fields(mock_geo, client):
    context = create_test_ckks_context()
    data = {
        "ckks_context": context.serialize().decode("ISO-8859-1")
    }
    response = client.post(
        "/submit-mobile-node-location-prop-ckks",
        data=json.dumps(data),
        content_type="application/json"
    )
    assert response.status_code == 400
    response_json = response.get_json()
    assert response_json["status"] == "error"