from flask import request
from normalizer import normalize_input_dict

class SentinelWallMiddleware:
    def __init__(self, app):
        self.app = app
        app.before_request(self.before_request)

    def before_request(self):
        input_data = {}

        if request.method == 'GET':
            input_data = request.args.to_dict(flat=True)
        elif request.is_json:
            input_data = request.get_json(force=True, silent=True) or {}
        else:
            input_data = request.form.to_dict(flat=True)

        # Normalize + Scan
        normalized_data = normalize_input_dict(input_data)
        request.normalized_data = normalized_data  # Attach to request
