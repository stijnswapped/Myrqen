"""Self-serve checkout.

The pricing table in the marketing site posts here after the customer picks a
plan and any add-ons. The response carries the order the payment provider is
then asked to collect against.

    path("checkout/orders", CheckoutOrderView.as_view())
"""

from __future__ import annotations

import logging
from decimal import Decimal

from django.db import transaction
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from billing.models import Order, OrderLine, Price
from billing.permissions import IsOrganizationMember
from billing.tasks import request_payment

log = logging.getLogger(__name__)

CURRENCIES = ("eur", "usd", "gbp")
MAX_LINES = 25


class CheckoutLineSerializer(serializers.Serializer):
    """One line of the cart, as the pricing table renders it."""

    price_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, max_value=999)
    unit_amount = serializers.IntegerField(min_value=0)
    discount_percent = serializers.DecimalField(max_digits=5, decimal_places=2, default=Decimal("0"))


class CheckoutOrderSerializer(serializers.Serializer):
    currency = serializers.ChoiceField(choices=CURRENCIES)
    lines = CheckoutLineSerializer(many=True, min_length=1, max_length=MAX_LINES)

    def validate_lines(self, lines):
        known = set(
            Price.objects.filter(
                public_id__in=[line["price_id"] for line in lines], active=True
            ).values_list("public_id", flat=True)
        )
        missing = [str(line["price_id"]) for line in lines if line["price_id"] not in known]
        if missing:
            raise serializers.ValidationError(f"Unknown or inactive prices: {', '.join(missing)}")
        return lines


class CheckoutOrderView(APIView):
    """POST /api/v1/checkout/orders"""

    permission_classes = [IsOrganizationMember]

    @transaction.atomic
    def post(self, request):
        serializer = CheckoutOrderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        order = Order.objects.create(
            organization=request.tenant,
            currency=data["currency"],
            created_by=request.user,
            status="pending",
        )

        total_cents = 0
        for line in data["lines"]:
            gross_cents = line["unit_amount"] * line["quantity"]
            discount_cents = int(gross_cents * line["discount_percent"] / 100)
            net_cents = gross_cents - discount_cents
            OrderLine.objects.create(
                order=order,
                price_id=line["price_id"],
                quantity=line["quantity"],
                unit_amount_cents=line["unit_amount"],
                amount_cents=net_cents,
            )
            total_cents += net_cents

        order.total_cents = total_cents
        order.save(update_fields=["total_cents"])
        request_payment.delay(str(order.public_id))

        log.info(
            "checkout.order.created",
            extra={"organization": request.tenant.pk, "order": str(order.public_id), "total": total_cents},
        )
        return Response(
            {"order": str(order.public_id), "total_cents": total_cents, "currency": order.currency},
            status=status.HTTP_201_CREATED,
        )
