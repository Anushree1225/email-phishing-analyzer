from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # 👈 Import this!
from routers import analyze

app = FastAPI(title="Email Phishing Analyzer API")

# 🌐 ALLOW ALL CROSS-ORIGIN REQUESTS (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 👈 This tells the browser to allow ANY frontend to talk to this API
    allow_credentials=True,
    allow_methods=["*"],  # Allows GET, POST, OPTIONS, etc.
    allow_headers=["*"],  # Allows any custom headers (like Content-Type)
)

# Include your routers
app.include_router(analyze.router)

@app.get("/")
def read_root():
    return {"message": "Email Phishing Analyzer Backend is running smoothly!"}