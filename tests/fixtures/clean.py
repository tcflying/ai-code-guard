# Clean code — should pass with minimal findings
def clean_function():
    """A safe function with no AI vulnerabilities."""
    import os
    import json

    api_key = os.environ.get("API_KEY")
    if not api_key:
        raise ValueError("API_KEY environment variable not set")

    return {"status": "ok"}
