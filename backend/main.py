# backend/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers.analyze import router

app = FastAPI(title="Email Phishing Analyzer")

# 1. Explicitly list your frontend Codespaces domain
origins = [
    "https://effective-space-engine-699g7rrqrx67cgp4-3000.app.github.dev",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,       # 👈 Use the explicit list instead of "*"
    allow_credentials=True,     # 👈 Must be True for Codespaces cookies/headers
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)