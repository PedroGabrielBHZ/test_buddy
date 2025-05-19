from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import re
import httpx
from typing import List, Dict, Any
from fastapi import status
from collections import OrderedDict
from log_utils import log_ip
import time

app = FastAPI()

templates = Jinja2Templates(directory="templates")

# curl -H "Accept: application/vnd.github.v3.diff" commit_url
# curl -H "Accept: application/vnd.github.v3.diff" https://api.github.com/repos/VictoriaMetrics/VictoriaMetrics/commits/f77dde837a043da1e628dd4390da43f769d7621a


# Global variable to store the submitted data
cache = {}
report = {"BEFORE": [], "AFTER": []}


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
                parse_start = time.time()
                try:
                    results[url] = resp.json()
                    parse_end = time.time()
                    log_ip(
                        f"JSON parse time for {url}: {parse_end - parse_start:.4f} seconds"
                    )
                except Exception:
                    results[url] = resp.text
                    parse_end = time.time()
                    log_ip(
                        f"Text parse time for {url}: {parse_end - parse_start:.4f} seconds"
                    )
            except Exception as e:
                results[url] = f"Error: {e}"
    return results


async def process_and_cache_urls(text_blob: str):
    urls = extract_urls_from_text_blob(text_blob)
    if len(urls) != 4:
        # Clear cache and report to "crash/reinitialize"
        cache.clear()
        report["BEFORE"].clear()
        report["AFTER"].clear()
        raise HTTPException(
            status_code=400,
            detail=f"Expected exactly 4 URLs in the text blob, but found {len(urls)}. Please re-submit with the correct input.",
        )
    cache["urls"] = urls

    # Organize URLs into before/after and json/log
    before_json, before_log, after_json, after_log = (urls + [None] * 4)[:4]
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

    for url in url_map.values():
        if url:
            log_ip(f"Fetched URL: {url}")

    cache["before"]["json"] = contents.get(before_json)
    cache["before"]["log"] = contents.get(before_log)
    cache["after"]["json"] = contents.get(after_json)
    cache["after"]["log"] = contents.get(after_log)

    # Log built cache size
    import sys

    cache_size = sys.getsizeof(cache)
    log_ip(f"Cache size after build: {cache_size} bytes")


@app.middleware("http")
async def log_request_ip(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    log_ip(client_ip)
    response = await call_next(request)
    return response


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "cache": cache}
    )


@app.post("/submit", response_class=HTMLResponse)
async def submit_data(request: Request, text_blob: str = Form(...)):
    cache["text_blob"] = text_blob
    urls = extract_urls_from_text_blob(text_blob)
    if len(urls) != 4:
        # Clear cache and report to "crash/reinitialize"
        cache.clear()
        report["BEFORE"].clear()
        report["AFTER"].clear()
        warning = f"Expected exactly 4 URLs in the text blob, but found {len(urls)}. Please re-submit with the correct input."
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "cache": cache, "warning": warning},
        )
    # Organize URLs into before/after and json/log
    before_json, before_log, after_json, after_log = (urls + [None] * 4)[:4]
    cache["urls"] = urls
    cache["before_json_url"] = before_json
    cache["after_json_url"] = after_json
    cache["before_log_url"] = before_log
    cache["after_log_url"] = after_log

    # Ask for user confirmation before fetching
    return templates.TemplateResponse(
        "confirm_urls.html",
        {
            "request": request,
            "before_json_url": before_json,
            "after_json_url": after_json,
            "before_log_url": before_log,
            "after_log_url": after_log,
            "text_blob": text_blob,
        },
    )


@app.post("/confirm_urls", response_class=HTMLResponse)
async def confirm_urls(request: Request, text_blob: str = Form(...)):
    await process_and_cache_urls(text_blob)
    return RedirectResponse(url="/check_test", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/check_test", response_class=HTMLResponse)
async def check_test_form(request: Request):
    return templates.TemplateResponse(
        "check_test.html", {"request": request, "result": None, "report": report}
    )


@app.post("/check_test", response_class=HTMLResponse)
async def check_test_result(request: Request, test_name: str = Form(...)):
    before_json = cache.get("before", {}).get("json")
    after_json = cache.get("after", {}).get("json")
    result = {}

    def find_test(json_data, name):
        if isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, dict) and item.get("name") == name:
                    return item
        elif isinstance(json_data, dict):
            for v in json_data.values():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and item.get("name") == name:
                            return item
        return None

    before_test = find_test(before_json, test_name)
    after_test = find_test(after_json, test_name)

    if before_test and after_test:
        result["found_in_before"] = True
        result["found_in_after"] = True
        result["before_status"] = before_test.get("status")
        result["after_status"] = after_test.get("status")
        result["status_changed"] = (
            before_test.get("status") == "FAILED"
            and after_test.get("status") == "PASSED"
        )
        result["before_test"] = before_test
        result["after_test"] = after_test
    else:
        result["found_in_before"] = bool(before_test)
        result["found_in_after"] = bool(after_test)
        result["status_changed"] = False
        result["before_test"] = before_test
        result["after_test"] = after_test

    return templates.TemplateResponse(
        "check_test.html",
        {
            "request": request,
            "result": result,
            "test_name": test_name,
            "report": report,
        },
    )


@app.post("/add_to_report")
async def add_to_report(test_name: str = Form(...)):
    global report
    before_json = cache.get("before", {}).get("json")
    after_json = cache.get("after", {}).get("json")

    def find_test(json_data, name):
        if isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, dict) and item.get("name") == name:
                    return item
        elif isinstance(json_data, dict):
            for v in json_data.values():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and item.get("name") == name:
                            return item
        return None

    before_test = find_test(before_json, test_name)
    after_test = find_test(after_json, test_name)

    # Ensure BEFORE comes before AFTER in the report dict
    if before_test and before_test not in report["BEFORE"]:
        report["BEFORE"].append(before_test)
    if after_test and after_test not in report["AFTER"]:
        report["AFTER"].append(after_test)

    # Reorder keys to ensure BEFORE is first
    report = OrderedDict([("BEFORE", report["BEFORE"]), ("AFTER", report["AFTER"])])

    return RedirectResponse(url="/check_test", status_code=303)


@app.post("/reset")
async def reset_cache():
    global report
    cache.clear()
    report = OrderedDict([("BEFORE", []), ("AFTER", [])])
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/reset_report")
async def reset_report():
    global report
    report = OrderedDict([("BEFORE", []), ("AFTER", [])])
    return RedirectResponse(url="/check_test", status_code=303)


@app.get("/fail_to_pass_report", response_class=HTMLResponse)
async def fail_to_pass_report(request: Request):
    # Use the current cache, not the report
    before_json = cache.get("before", {}).get("json")
    after_json = cache.get("after", {}).get("json")

    def get_tests(json_data):
        if isinstance(json_data, list):
            return [
                t
                for t in json_data
                if isinstance(t, dict) and "name" in t and "status" in t
            ]
        elif isinstance(json_data, dict):
            tests = []
            for v in json_data.values():
                if isinstance(v, list):
                    tests.extend(
                        [
                            t
                            for t in v
                            if isinstance(t, dict) and "name" in t and "status" in t
                        ]
                    )
            return tests
        return []

    before_tests_list = get_tests(before_json)
    after_tests_list = get_tests(after_json)
    before_tests = {t["name"]: t for t in before_tests_list}
    after_tests = {t["name"]: t for t in after_tests_list}

    # Count occurrences for uniqueness
    from collections import Counter

    before_counts = Counter(t["name"] for t in before_tests_list)
    after_counts = Counter(t["name"] for t in after_tests_list)

    fail_to_pass = []
    for name, before in before_tests.items():
        after = after_tests.get(name)
        if (
            after
            and before.get("status") == "FAILED"
            and after.get("status") == "PASSED"
        ):
            fail_to_pass.append(
                {
                    "name": name,
                    "before_status": before.get("status"),
                    "after_status": after.get("status"),
                    "before": before,
                    "after": after,
                    "not_unique_before": before_counts[name] > 1,
                    "not_unique_after": after_counts[name] > 1,
                }
            )
    return templates.TemplateResponse(
        "fail_to_pass_report.html", {"request": request, "fail_to_pass": fail_to_pass}
    )
