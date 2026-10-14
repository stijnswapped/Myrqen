"""Celery tasks for the billing app."""

from __future__ import annotations

import logging

from celery import shared_task

log = logging.getLogger(__name__)


@shared_task(name="billing.schedule_proration_run")
def schedule_proration_run(subscription_public_id: str) -> None:
    log.info("proration.scheduled", extra={"subscription": subscription_public_id})


@shared_task(name="billing.sync_payment_method")
def sync_payment_method(method_public_id: str) -> None:
    log.info("payment_method.sync", extra={"method": method_public_id})


@shared_task(name="billing.request_payment")
def request_payment(order_public_id: str) -> None:
    log.info("payment.requested", extra={"order": order_public_id})
