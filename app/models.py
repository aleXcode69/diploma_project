from pydantic import BaseModel, Field


class HandshakeRequest(BaseModel):
    pq_public_key: str = Field(..., min_length=10)
    classic_public_key: str = Field(..., min_length=10)


class HandshakeResponse(BaseModel):
    session_id: str
    pq_ciphertext: str
    server_classic_public_key: str


class ProtectedResponse(BaseModel):
    session_id: str
    message: str
    proof: str
