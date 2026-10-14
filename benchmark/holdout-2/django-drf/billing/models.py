"""Billing domain models.

Every row that belongs to a customer carries an ``organization`` foreign key.
Nothing in this module enforces that a request may see a given row — see
``billing/tenancy.py`` for where the tenant comes from and whose job it is to
apply it.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class Plan(models.Model):
    code = models.SlugField(unique=True)
    name = models.CharField(max_length=120)
    seat_limit = models.PositiveIntegerField(default=5)


class Organization(models.Model):
    """A customer. This is the tenant boundary."""

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=200)
    billing_email = models.EmailField()
    billing_country = models.CharField(max_length=2, default="NL")
    default_currency = models.CharField(max_length=3, default="eur")
    webhook_secret = models.CharField(max_length=128)

    # Commercial state. Only the provisioning service and the billing operators
    # are supposed to move these.
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="organizations")
    seat_limit = models.PositiveIntegerField(default=5)
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    is_tax_exempt = models.BooleanField(default=False)
    credit_balance_cents = models.BigIntegerField(default=0)
    mrr_cents = models.BigIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class BillingContact(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="contacts")
    display_name = models.CharField(max_length=200)
    email = models.EmailField()
    phone = models.CharField(max_length=40, blank=True)
    locale = models.CharField(max_length=10, default="en")
    receives_dunning = models.BooleanField(default=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Subscription(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="subscriptions")
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="subscriptions")
    status = models.CharField(max_length=24, default="trialing")
    quantity = models.PositiveIntegerField(default=1)
    canceled_at = models.DateTimeField(null=True, blank=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)


class SubscriptionItem(models.Model):
    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE, related_name="items")
    code = models.SlugField()
    quantity = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)


class PaymentMethod(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="payment_methods")
    provider_token = models.CharField(max_length=200)
    brand = models.CharField(max_length=24)
    last4 = models.CharField(max_length=4)
    status = models.CharField(max_length=24, default="pending_verification")
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class PaymentMethodEvent(models.Model):
    method = models.ForeignKey(PaymentMethod, on_delete=models.CASCADE, related_name="events")
    kind = models.CharField(max_length=40)
    created_at = models.DateTimeField(auto_now_add=True)


class Price(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name="prices")
    currency = models.CharField(max_length=3, default="eur")
    unit_amount_cents = models.PositiveIntegerField()
    discount_percent = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    active = models.BooleanField(default=True)


class Order(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="orders")
    currency = models.CharField(max_length=3, default="eur")
    total_cents = models.BigIntegerField(default=0)
    status = models.CharField(max_length=24, default="pending")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)


class OrderLine(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="lines")
    price = models.ForeignKey(Price, on_delete=models.PROTECT, to_field="public_id", db_column="price_id")
    quantity = models.PositiveIntegerField(default=1)
    unit_amount_cents = models.PositiveIntegerField()
    amount_cents = models.BigIntegerField()


class Invoice(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="invoices")
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="invoices")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    currency = models.CharField(max_length=3, default="eur")
    total_cents = models.BigIntegerField(default=0)
    status = models.CharField(max_length=24, default="open")
    issued_at = models.DateTimeField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)


class WebhookDelivery(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="webhook_deliveries")
    target_url = models.URLField(max_length=2048)
    event_type = models.CharField(max_length=60)
    response_status = models.PositiveIntegerField(null=True)
    probe = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class NotificationReceiver(models.Model):
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="receivers")
    target_url = models.URLField(max_length=2048)
    verified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class NotificationDelivery(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="notice_deliveries")
    receiver = models.ForeignKey(NotificationReceiver, on_delete=models.CASCADE, related_name="deliveries")
    notice_type = models.CharField(max_length=60)
    response_status = models.PositiveIntegerField(null=True)
    probe = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
