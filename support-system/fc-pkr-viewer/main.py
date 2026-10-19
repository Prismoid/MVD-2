import os
import httpx

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PKR_URL = os.getenv("PKR_URL", "http://localhost:7450")
CAT_URL = os.getenv("CAT_URL", "http://localhost:7451")

app = FastAPI(title="MVD Browser")

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def index():
    return FileResponse("static/index.html")


async def request_json(method: str, url: str, **kwargs):
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.request(method, url, **kwargs)

    if res.status_code >= 400:
        raise HTTPException(res.status_code, res.text)

    if not res.content:
        return {"status": "ok"}

    try:
        return res.json()
    except Exception:
        return {"status": "ok", "body": res.text}


@app.get("/api/fc")
async def get_federated_catalog(
    resource_id: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
):
    params = {}
    if resource_id:
        params["resource_id"] = resource_id
    if user_id:
        params["user_id"] = user_id
    if keyword:
        params["keyword"] = keyword

    return await request_json("GET", f"{CAT_URL}/fc/get", params=params)


@app.delete("/api/fc/debug/delete-all")
async def delete_all_federated_catalog():
    return await request_json("DELETE", f"{CAT_URL}/fc/debug/delAll")


@app.get("/api/pkr/{user_id}")
async def get_public_key(user_id: str):
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.get(f"{PKR_URL}/pkr/get/{user_id}")

    if res.status_code == 404:
        return None

    if res.status_code >= 400:
        raise HTTPException(res.status_code, res.text)

    return res.json()


@app.get("/api/pkr")
async def get_all_public_keys():
    return await request_json("GET", f"{PKR_URL}/pkr/debug/showAllKeys")


@app.delete("/api/pkr/debug/delete-all")
async def delete_all_public_keys():
    return await request_json("DELETE", f"{PKR_URL}/pkr/debug/delAllKeys")
