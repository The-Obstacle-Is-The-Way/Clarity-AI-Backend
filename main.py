"""
Clarity-AI FastAPI Application
=============================
Main entry point for the Clarity-AI psychiatric platform.
Implements HIPAA-compliant API with proper security measures.

This file serves as a simple entry point for running the application.
The actual FastAPI application is defined in app/main.py and imported here.
"""

# Import the application instance from the app module
from app.main import app

# This enables uvicorn to run the application when specified as 'main:app'
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
