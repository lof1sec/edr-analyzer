from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app import models, database
from app.routers import datasets, graph

# Create tables if they don't exist
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="EDR Logs Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(datasets.router)
app.include_router(graph.router)

@app.get("/")
def read_root():
    return {"status": "ok"}
