import re
import httpx
from typing import List, Dict, Any
from fastapi import HTTPException
import time as _time

# Session helpers


def get_session_id(
    request, response, SESSION_COOKIE_NAME, SESSION_COOKIE_MAX_AGE, session_times, uuid
):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    now = int(_time.time())
    if not session_id:
        session_id = str(uuid.uuid4())
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            max_age=SESSION_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        session_times[session_id] = now
    else:
        # Update last access time
        session_times[session_id] = now
    return session_id


def get_user_cache(
    session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
):
    # Check for session expiry
    now = int(_time.time())
    last_access = session_times.get(session_id)
    if last_access is not None and now - last_access > SESSION_COOKIE_MAX_AGE:
        user_caches.pop(session_id, None)
        user_reports.pop(session_id, None)
        session_times.pop(session_id, None)
        return {}
    return user_caches.setdefault(session_id, {})


def get_user_report(
    session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
):
    # Check for session expiry
    now = int(_time.time())
    last_access = session_times.get(session_id)
    if last_access is not None and now - last_access > SESSION_COOKIE_MAX_AGE:
        user_caches.pop(session_id, None)
        user_reports.pop(session_id, None)
        session_times.pop(session_id, None)
        return {"BEFORE": [], "AFTER": []}
    return user_reports.setdefault(session_id, {"BEFORE": [], "AFTER": []})


def extract_urls_from_text_blob(text):
    """
    Extracts all URLs from cache["text_blob"] and returns them as a list.
    Returns an empty list if text_blob is not present.
    """
    # Simple regex for URLs (http/https)
    url_pattern = r'https?://[^\s"]+'
    return re.findall(url_pattern, text)


async def fetch_url_contents(urls: List[str]) -> Dict[str, Any]:
    """
    Fetches the content of each URL in the list.
    If the content is JSON, parses it; otherwise, returns as text.
    Returns a dict mapping url -> content.
    Logs JSON parsing times for each URL.
    """
    results = {}
    async with httpx.AsyncClient() as client:
        for url in urls:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                try:
                    results[url] = resp.json()
                except Exception:
                    results[url] = resp.text
            except Exception as e:
                results[url] = f"Error: {e}"
    return results


async def process_and_cache_urls(
    text_blob: str, user_cache=None, user_report=None, cache=None
):
    urls = extract_urls_from_text_blob(text_blob)
    if len(urls) != 4:
        # Clear cache and report to "crash/reinitialize"
        if user_cache is not None:
            user_cache.clear()
        if user_report is not None:
            user_report["BEFORE"].clear()
            user_report["AFTER"].clear()
        raise HTTPException(
            status_code=400,
            detail=f"Expected exactly 4 URLs in the text blob, but found {len(urls)}. Please re-submit with the correct input.",
        )
    if user_cache is not None:
        user_cache["urls"] = urls
    elif cache is not None:
        cache["urls"] = urls

    # Organize URLs into before/after and json/log
    before_json, before_log, after_json, after_log = (urls + [None] * 4)[:4]
    if user_cache is not None:
        user_cache["before"] = {"json_url": before_json, "log_url": before_log}
        user_cache["after"] = {"json_url": after_json, "log_url": after_log}
    elif cache is not None:
        cache["before"] = {"json_url": before_json, "log_url": before_log}
        cache["after"] = {"json_url": after_json, "log_url": after_log}

    # Fetch contents asynchronously
    url_map = {
        "before_json": before_json,
        "before_log": before_log,
        "after_json": after_json,
        "after_log": after_log,
    }
    contents = await fetch_url_contents([u for u in url_map.values() if u])

    if user_cache is not None:
        user_cache["before"]["json"] = contents.get(before_json)
        user_cache["before"]["log"] = contents.get(before_log)
        user_cache["after"]["json"] = contents.get(after_json)
        user_cache["after"]["log"] = contents.get(after_log)
    elif cache is not None:
        cache["before"]["json"] = contents.get(before_json)
        cache["before"]["log"] = contents.get(before_log)
        cache["after"]["json"] = contents.get(after_json)
        cache["after"]["log"] = contents.get(after_log)
