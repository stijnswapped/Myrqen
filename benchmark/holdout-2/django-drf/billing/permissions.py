"""Permission classes for the billing API.

These answer "may this account call this endpoint at all". They deliberately do
not implement ``has_object_permission``: a permission class that scoped objects
would only run on detail routes, and list routes would still leak. Scoping the
queryset is the only place that covers both, so that is where it belongs.
"""

from __future__ import annotations

from rest_framework.permissions import BasePermission

BILLING_ROLES = ("owner", "billing_admin")


class IsOrganizationMember(BasePermission):
    message = "This account is not a member of any organization."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(request, "tenant", None) is not None)


class IsBillingAdmin(BasePermission):
    message = "Billing administrator access is required."

    def has_permission(self, request, view):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        membership = request.user.memberships.filter(organization=request.tenant).first()
        return membership is not None and membership.role in BILLING_ROLES
