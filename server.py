import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class HashRequest(BaseModel):
    user_id: str
    private_key: str

@app.post("/hash")
def generate_hash(request: HashRequest):
    input_string = request.user_id + request.private_key
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    hex_digest = sha256_hash.hexdigest()
    truncated_hex_digest = hex_digest[:40]
    
    return {"hash": truncated_hex_digest}

