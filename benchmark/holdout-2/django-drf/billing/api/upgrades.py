"""In-product plan upgrades.

The plan switcher posts here when an existing customer moves to a larger plan or
adds seats. The response carries the order the payment provider is then asked to
collect against.

    path("checkout/upgrades", UpgradeOrderView.as_view())
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


class UpgradeLineSerializer(serializers.Serializer):
    """One line of the upgrade, as the plan switcher renders it.

    ``unit_amount`` is the figure the browser had on screen. It is an optimistic
    concurrency check, not an input: if the catalogue moved between render and
    submit we would rather fail than charge a price the customer never saw. The
    amount actually charged is always the one on the Price row.
    """

    price_id = serializers.UUIDField()
    quantity = serializers.IntegerField(min_value=1, max_value=999)
    unit_amount = serializers.IntegerField(min_value=0, write_only=True, required=False)
    discount_percent = serializers.DecimalField(
        max_digits=5, decimal_places=2, read_only=True, default=Decimal("0")
    )


class UpgradeOrderSerializer(serializers.Serializer):
    currency = serializers.ChoiceField(choices=CURRENCIES)
    lines = UpgradeLineSerializer(many=True, min_length=1, max_length=MAX_LINES)

    def validate_lines(self, lines):
        prices = Price.objects.filter(
            public_id__in=[line["price_id"] for line in lines], active=True
        ).in_bulk(field_name="public_id")

        for line in lines:
            price = prices.get(line["price_id"])
            if price is None:
                raise serializers.ValidationError(f"Unknown or inactive price: {line['price_id']}")
            quoted = line.get("unit_amount")
            if quoted is not None and quoted != price.unit_amount_cents:
                raise serializers.ValidationError(
                    "This price changed while you were checking out. Reload and try again."
                )
            line["price"] = price
        return lines


class UpgradeOrderView(APIView):
    """POST /api/v1/checkout/upgrades"""

    permission_classes = [IsOrganizationMember]

    @transaction.atomic
    def post(self, request):
        serializer = UpgradeOrderSerializer(data=request.data)
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
            price = line["price"]
            gross_cents = price.unit_amount_cents * line["quantity"]
            discount_cents = int(gross_cents * price.discount_percent / 100)
            net_cents = gross_cents - discount_cents
            OrderLine.objects.create(
                order=order,
                price=price,
                quantity=line["quantity"],
                unit_amount_cents=price.unit_amount_cents,
                amount_cents=net_cents,
            )
            total_cents += net_cents

        order.total_cents = total_cents
        order.save(update_fields=["total_cents"])
        request_payment.delay(str(order.public_id))

        log.info(
            "checkout.upgrade.created",
            extra={"organization": request.tenant.pk, "order": str(order.public_id), "total": total_cents},
        )
        return Response(
            {"order": str(order.public_id), "total_cents": total_cents, "currency": order.currency},
            status=status.HTTP_201_CREATED,
        )
