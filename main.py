from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from typing import List, Dict, Any
from fastapi import status
from collections import OrderedDict
import uuid

from tools import (
    get_session_id,
    get_user_cache,
    get_user_report,
    extract_urls_from_text_blob,
    fetch_url_contents,
    process_and_cache_urls,
)

app = FastAPI()

templates = Jinja2Templates(directory="templates")

# Global variable to store the submitted data
cache = {}
report = {"BEFORE": [], "AFTER": []}

# Per-session storage
user_caches = {}
user_reports = {}

SESSION_COOKIE_NAME = "session_id"
SESSION_COOKIE_MAX_AGE = 60 * 30  # 30 minutes

# Store session creation/last-access times for expiry
session_times = {}

import time as _time


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    session_id = get_session_id(
        request,
        Response(),
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    response = templates.TemplateResponse(
        "index.html",
        {"request": request, "cache": user_cache},
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/submit", response_class=HTMLResponse)
async def submit_data(request: Request, text_blob: str = Form(...)):
    response = Response()
    session_id = get_session_id(
        request,
        response,
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_cache["text_blob"] = text_blob
    urls = extract_urls_from_text_blob(text_blob)
    if len(urls) != 4:
        user_cache.clear()
        user_report["BEFORE"].clear()
        user_report["AFTER"].clear()
        warning = f"Expected exactly 4 URLs in the text blob, but found {len(urls)}. Please re-submit with the correct input."
        template_response = templates.TemplateResponse(
            "index.html",
            {"request": request, "cache": user_cache, "warning": warning},
        )
        template_response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            max_age=SESSION_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
        )
        return template_response
    before_json, before_log, after_json, after_log = (urls + [None] * 4)[:4]
    user_cache["urls"] = urls
    user_cache["before_json_url"] = before_json
    user_cache["after_json_url"] = after_json
    user_cache["before_log_url"] = before_log
    user_cache["after_log_url"] = after_log
    template_response = templates.TemplateResponse(
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
    template_response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return template_response


@app.post("/confirm_urls", response_class=HTMLResponse)
async def confirm_urls(request: Request, text_blob: str = Form(...)):
    session_id = get_session_id(
        request,
        Response(),
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    await process_and_cache_urls(text_blob, user_cache, user_report)
    response = RedirectResponse(
        url="/check_test", status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/check_test", response_class=HTMLResponse)
async def check_test_form(request: Request):
    response = Response()
    session_id = get_session_id(
        request,
        response,
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    template_response = templates.TemplateResponse(
        "check_test.html",
        {"request": request, "result": None, "report": user_report},
    )
    template_response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return template_response


@app.post("/check_test", response_class=HTMLResponse)
async def check_test_result(request: Request, test_name: str = Form(...)):
    response = Response()
    session_id = get_session_id(
        request,
        response,
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    before_json = user_cache.get("before", {}).get("json")
    after_json = user_cache.get("after", {}).get("json")
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
    template_response = templates.TemplateResponse(
        "check_test.html",
        {
            "request": request,
            "result": result,
            "test_name": test_name,
            "report": user_report,
        },
    )
    template_response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return template_response


@app.post("/add_to_report")
async def add_to_report(request: Request, test_name: str = Form(...)):
    session_id = get_session_id(
        request,
        Response(),
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    before_json = user_cache.get("before", {}).get("json")
    after_json = user_cache.get("after", {}).get("json")

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
    if before_test and before_test not in user_report["BEFORE"]:
        user_report["BEFORE"].append(before_test)
    if after_test and after_test not in user_report["AFTER"]:
        user_report["AFTER"].append(after_test)
    user_report = OrderedDict(
        [("BEFORE", user_report["BEFORE"]), ("AFTER", user_report["AFTER"])]
    )
    response = RedirectResponse(url="/check_test", status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/reset")
async def reset_cache(request: Request):
    session_id = get_session_id(
        request,
        Response(),
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_cache.clear()
    user_report["BEFORE"].clear()
    user_report["AFTER"].clear()
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/reset_report")
async def reset_report(request: Request):
    session_id = get_session_id(
        request,
        Response(),
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_report = get_user_report(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    user_report["BEFORE"].clear()
    user_report["AFTER"].clear()
    response = RedirectResponse(url="/check_test", status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/fail_to_pass_report", response_class=HTMLResponse)
async def fail_to_pass_report(request: Request):
    response = Response()
    session_id = get_session_id(
        request,
        response,
        SESSION_COOKIE_NAME,
        SESSION_COOKIE_MAX_AGE,
        session_times,
        uuid,
    )
    user_cache = get_user_cache(
        session_id, session_times, SESSION_COOKIE_MAX_AGE, user_caches, user_reports
    )
    before_json = user_cache.get("before", {}).get("json")
    after_json = user_cache.get("after", {}).get("json")

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
    template_response = templates.TemplateResponse(
        "fail_to_pass_report.html",
        {"request": request, "fail_to_pass": fail_to_pass},
    )
    template_response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return template_response
