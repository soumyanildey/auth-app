import os
from django.http import FileResponse
from django.conf import settings

def serve_static_index(request):
    index_path = os.path.join(settings.BASE_DIR, 'static', 'index.html')
    return FileResponse(open(index_path, 'rb'), content_type='text/html')
