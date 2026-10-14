"""URL configuration."""

from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from billing.api.checkout import CheckoutOrderView
from billing.api.contacts import BillingContactViewSet
from billing.api.exports import receivables_ageing
from billing.api.notifications import NotificationProbeView
from billing.api.organizations import OrganizationViewSet
from billing.api.payment_methods import PaymentMethodViewSet
from billing.api.reports import revenue_breakdown
from billing.api.subscriptions import SubscriptionViewSet
from billing.api.upgrades import UpgradeOrderView
from billing.api.webhooks import WebhookProbeView
from documents.api.archive import InvoiceArchiveView
from documents.api.attachments import CreditNoteAttachmentView

router = DefaultRouter()
router.register("subscriptions", SubscriptionViewSet, basename="subscription")
router.register("payment-methods", PaymentMethodViewSet)
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("billing-contacts", BillingContactViewSet, basename="billing-contact")

api = [
    path("", include(router.urls)),
    path("reports/revenue", revenue_breakdown),
    path("reports/ageing", receivables_ageing),
    path("checkout/orders", CheckoutOrderView.as_view()),
    path("checkout/upgrades", UpgradeOrderView.as_view()),
    path("webhook-endpoints/probe", WebhookProbeView.as_view()),
    path("notification-receivers/probe", NotificationProbeView.as_view()),
    path("documents/archive/<path:relative_path>", InvoiceArchiveView.as_view()),
    path("documents/attachments/<path:relative_path>", CreditNoteAttachmentView.as_view()),
]

urlpatterns = [path("api/v1/", include(api))]
