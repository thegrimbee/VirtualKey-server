import hashlib
from fastapi import FastAPI, HTTPException
import random
import string
from pydantic import BaseModel
import json

app = FastAPI()
database = json.load(open("database.json"))
SALT = "s3Cre7_85927"

def get_user_key(username):
    return database["users"].get(username)["key"]

def generate_random_key(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

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
    if request.username in database["users"]:
        raise HTTPException(status_code=400, detail="User already exists")
    
    database["users"][request.username] = {"key": request.received_hash}
    json.dump(database, open("database.json", "w"))
    return {"username": request.username, "key": request.received_hash}

@app.post("/login")
def login_user(request: ValidationRequest):
    if request.username not in database["users"]:
        raise HTTPException(status_code=400, detail="User does not exist")
    sha256_hash = hashlib.sha256()
    input_string = request.password + SALT
    sha256_hash.update(input_string.encode('utf-8'))
    if sha256_hash.hexdigest() != database["users"][request.username]["hash"]:
        raise HTTPException(status_code=400, detail="Invalid password")
    return {"username": request.username}

@app.post("/test")
def test(request: ValidationRequest):
    return {"username": request.username}