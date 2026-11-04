"""Application-owned portal boundary for a gateway's restricted website route."""
from starlette.responses import JSONResponse, RedirectResponse


def portal_path(path):
    return path in ('/portal', '/api/portal') or path.startswith(('/api/portal/', '/static/'))


class PortalBoundary:
    """The gateway can restrict a request; this header never grants privileges."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        restricted = scope['type'] == 'http' and any(key == b'x-openvpn-portal-only' and value == b'1' for key, value in scope.get('headers', []))
        if restricted and not portal_path(scope['path']):
            response = RedirectResponse('/portal', status_code=303) if scope['path'] == '/' else JSONResponse({'detail': 'Not found'}, status_code=404)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
