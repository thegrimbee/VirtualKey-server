import pytest
from fastapi.testclient import TestClient
from server import app
import hashlib
import json

client = TestClient(app)
SALT = "s3Cre7_85927"
database = json.load(open("database.json"))
users = database.get("users")
example_key = users.get("example")["key"]

def test_generate_hash():
    input_string = example_key + SALT
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    response = client.post("/validate", json={"username": "example", "received_hash": sha256_hash.hexdigest()[:40]})
    response2 = client.post("/validate", json={"username": "example", "received_hash": "invalid_hash"})
    assert response.status_code == 200
    assert response.json() == {"username": "example", "is_valid": True}
    assert response2.status_code == 200
    assert response2.json() == {"username": "example", "is_valid": False}

test_generate_hash()