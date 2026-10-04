"""Flask app serving the dashboard UI and streaming state to it via SSE.

Server-Sent Events rather than WebSockets: the flow is strictly one-way
(server -> browser), SSE needs no extra dependency beyond Flask itself, and
browsers reconnect a dropped EventSource automatically -- useful when the PC
or Pi is restarted mid-campaign.
"""

import json
import os
import time

from flask import Flask, Response, jsonify, send_from_directory

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
DEFAULT_STREAM_HZ = 10.0


def create_app(store, stream_hz=DEFAULT_STREAM_HZ, static_dir=STATIC_DIR):
    app = Flask(__name__, static_folder=None)
    app.config['STORE'] = store
    app.config['STREAM_INTERVAL_S'] = 1.0 / stream_hz

    @app.route('/')
    def index():
        return send_from_directory(static_dir, 'index.html')

    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory(static_dir, filename)

    @app.route('/api/state')
    def api_state():
        return jsonify(store.snapshot())

    @app.route('/api/health')
    def api_health():
        snap = store.snapshot()
        return jsonify({
            'ok': True,
            'uptime_s': snap['t'],
            'counts': snap['counts'],
            'receiving_trust_scores': snap['counts']['trust_scores'] > 0,
            'receiving_snapshots': snap['counts']['snapshots'] > 0,
        })

    @app.route('/api/stream')
    def api_stream():
        interval = app.config['STREAM_INTERVAL_S']

        def generate():
            while True:
                payload = json.dumps(store.snapshot())
                yield f'data: {payload}\n\n'
                time.sleep(interval)

        return Response(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive',
            },
        )

    return app
