"""Serializers shared by more than one viewset.

Anything written from a request names its fields explicitly. ``__all__`` on a
model that carries commercial state is how a customer ends up setting their own
seat limit.
"""

from __future__ import annotations

from rest_framework import serializers

from billing.models import PaymentMethod, Subscription, SubscriptionItem


class SubscriptionItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionItem
        fields = ("code", "quantity", "created_at")
        read_only_fields = fields


class SubscriptionSerializer(serializers.ModelSerializer):
    items = SubscriptionItemSerializer(many=True, read_only=True)
    plan_code = serializers.SlugField(source="plan.code", read_only=True)

    class Meta:
        model = Subscription
        fields = ("public_id", "plan_code", "status", "quantity", "items", "canceled_at", "created_at")
        read_only_fields = fields


class SubscriptionWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = ("plan", "quantity")


class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = ("public_id", "brand", "last4", "status", "revoked_at", "created_at")
        read_only_fields = fields


class PaymentMethodWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = ("provider_token",)
