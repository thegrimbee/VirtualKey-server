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

@app.post("/register")
def register_user(request: ValidationRequest):
    if request.username in users:
        raise HTTPException(status_code=400, detail="User already exists")
    database["users"][request.username] = {"key": request.received_hash}
    json.dump(database, open("database.json", "w"))
    return {"username": request.username, "key": request.received_hash}

@app.post("/login")
def login_user(request: ValidationRequest):
    if request.username not in users:
        raise HTTPException(status_code=400, detail="User does not exist")
    sha256_hash = hashlib.sha256()
    input_string = request.password + SALT
    sha256_hash.update(input_string.encode('utf-8'))
    if sha256_hash.hexdigest() != users[request.username]["hash"]:
        raise HTTPException(status_code=400, detail="Invalid password")
    return {"username": request.username, "key": users[request.username]["key"]}
