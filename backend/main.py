from fastapi import FastAPI
from routers.analyze import router

app = FastAPI(title="Email Phishing Analyzer")

app.include_router(router)