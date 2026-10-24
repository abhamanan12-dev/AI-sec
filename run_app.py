"""Quick Launcher for the AI Safety & Compliance Readiness Web Application."""

import sys
import webbrowser
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from safety_pipeline.core.config import ARTIFACTS_DIR
from safety_pipeline.cli import run_all


def main():
    parser = argparse.ArgumentParser(description="AI Safety & Compliance Readiness Studio Launcher")
    parser.add_argument("--refresh", action="store_true", help="Explicitly re-run assessment before launching dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host IP")
    parser.add_argument("--port", default=8000, type=int, help="Port number")
    args = parser.parse_args()

    print("=" * 70)
    print("  🛡️  AI Safety & Compliance Readiness Studio — Launcher")
    print("=" * 70)

    # Re-run only if explicitly requested with --refresh, or if reports have never been generated
    dashboard_path = ARTIFACTS_DIR / "compliance_dashboard.html"
    if args.refresh or not dashboard_path.exists():
        print("\n[Assessment] Generating/refreshing assessment artifacts...")
        run_all(mode="simulated")
    else:
        print("\n[Notice] Serving existing assessment artifacts from artifacts directory.")
        print("         To force a fresh re-assessment, pass '--refresh' or run:")
        print("         python -m safety_pipeline.cli run-all\n")

    import uvicorn
    url = f"http://{args.host}:{args.port}/"

    print(f"[Ready] Application running at: {url}")
    print("[Tips]")
    print(f" • Interactive Web Studio:          {url}")
    print(f" • OpenAI-Compatible Endpoint:     {url}v1/chat/completions")
    print(f" • Swagger REST API Docs:           {url}docs")
    print(f" • Press CTRL+C in this terminal to stop the server.\n")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    uvicorn.run("safety_pipeline.web.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
