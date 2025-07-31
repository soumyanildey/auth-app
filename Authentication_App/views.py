from django.http import FileResponse
from pathlib import Path

def serve_static_html(request, filename="index.html"):
    path = Path(__file__).resolve().parent.parent / "static" / filename
    return FileResponse(open(path, 'rb'), content_type='text/html')
