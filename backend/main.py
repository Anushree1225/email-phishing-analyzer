from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import analyze

app = FastAPI(title="Email Phishing Analyzer Engine")

# 🚀 Add your exact live cloud workspace URLs to the trusted whitelist
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://effective-space-engine-699g7rrqrx67cgp4-3000.app.github.dev", # Your live frontend browser link
    "https://effective-space-engine-699g7rrqrx67cgp4-8000.app.github.dev", # Your live backend proxy link
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            # 🌟 Grants clean passage to your specific browser workspace!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)

@app.get("/")
def root():
    return {"status": "healthy", "engine": "FastAPI Email Phishing Core"}