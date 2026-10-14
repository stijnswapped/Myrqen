"""Tenant resolution.

``TenantMiddleware`` runs after authentication and attaches the caller's
organization to the request as ``request.tenant``. It resolves the tenant; it
does not scope anything. Every queryset that touches a customer-owned table is
responsible for filtering on ``request.tenant`` itself, because the ORM has no
idea a request is in progress.
"""

from __future__ import annotations

from django.utils.functional import SimpleLazyObject
from rest_framework.exceptions import PermissionDenied

from billing.models import Organization


def _resolve(request) -> Organization | None:
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return None
    membership = user.memberships.select_related("organization__plan").first()
    if membership is None:
        raise PermissionDenied("This account is not a member of any organization.")
    return membership.organization


class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.tenant = SimpleLazyObject(lambda: _resolve(request))
        return self.get_response(request)
