# import uvicorn

# if __name__ == "__main__":
#     uvicorn.run(
#         "app.main:app",
#         host="localhost",
#         port=8000,
#         reload=True,
#         # ssl_keyfile="certs/localhost-key.pem",
#         # ssl_certfile="certs/localhost.pem"
#     )

import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",  # IMPORTANT
        port=int(os.environ.get("PORT", 8000))  # Use Railway's port
    )