import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="localhost",
        port=8000,
        reload=True,
        # ssl_keyfile="certs/localhost-key.pem",
        # ssl_certfile="certs/localhost.pem"
    )

