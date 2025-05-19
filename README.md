# Test Buddy

A FastAPI web application for comparing test results before and after a patch, focusing on tests that change from FAILED to PASSED.

## Features

- Submit a text blob containing four URLs (before/after JSON and log files).
- Asynchronously fetches and caches the test result files.
- Check individual test status transitions (FAILED → PASSED).
- Add checked tests to a report for later review.
- View a Fail-to-Pass (F2P) report listing all tests that transitioned from FAILED to PASSED.
- Detect and warn about non-unique test names in the JSON files.
- Reset cache and report at any time.
- Responsive, Bootstrap-styled UI.

## Usage

1. **Start the app:**
   ```
   uvicorn main:app --reload
   ```

2. **Open your browser:**  
   Go to [http://localhost:8000](http://localhost:8000)

3. **Submit Input:**
   - Paste a text blob containing exactly four URLs (before/after JSON and log files).
   - If the input is invalid, a warning will be shown.

4. **Check Tests:**
   - Enter a test name to check its status before and after the patch.
   - Optionally, add the test to the report.

5. **View Reports:**
   - Access the Fail-to-Pass report at any time using the floating button.
   - Reset cache and report using the floating red button.

## Input Format

The text blob must contain **exactly four URLs** in any order:
- Before JSON
- Before Log
- After JSON
- After Log

Example:
```
Test Results Before JSON: https://example.com/before.json
Test Results Before Log: https://example.com/before.log
Test Results After JSON: https://example.com/after.json
Test Results After Log: https://example.com/after.log
```

## Development

- Python 3.10+
- FastAPI
- httpx
- Bootstrap 5 (CDN)

## License

MIT
