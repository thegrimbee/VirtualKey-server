import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json

app = FastAPI()
database = json.load(open("database.json"))
users = database.get("users")
SALT = "s3Cre7_85927"

def get_user_key(username):
    return users.get(username)["key"]

class ValidationRequest(BaseModel):
    username: str
    received_hash: str

@app.post("/validate")
def generate_hash(request: ValidationRequest):
    hash_to_compare = request.received_hash
    user_key = get_user_key(request.username)
    input_string = user_key + SALT
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    hex_digest = sha256_hash.hexdigest()
    truncated_hex_digest = hex_digest[:40]
    return {"username": request.username, "is_valid": hash_to_compare == truncated_hex_digest}

