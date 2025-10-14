
from fastapi import FastAPI
from crypto_finder.api import endpoints

app = FastAPI(
    title="Crypto Finder API",
    description="API to fine cryptographic primitives in Firmware binaries",
    version="0.1.0"
)

app.include_router(endpoints.router, prefix="/api/v1", tags=["Analysis"])

@app.get("/", tags=["General"])
def read_root():

    return {"message": "Welcome to Crypto Finder API! For API documentation go to  /docs}
