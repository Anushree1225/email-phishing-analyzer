# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers.analyze import router

app = FastAPI(title="Email Phishing Analyzer")

# The ultimate fail-safe cloud proxy CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all cloud proxy origins dynamically
    allow_credentials=False, # Must be False when allow_origins is ["*"] to satisfy browser engines
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)