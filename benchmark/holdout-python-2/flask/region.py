from flask import Blueprint, abort, redirect, request, url_for

bp = Blueprint("region", __name__, url_prefix="/region")

SUPPORTED = {"eu", "us", "uk", "apac"}
ONE_YEAR = 60 * 60 * 24 * 365

RETURN_ENDPOINTS = {
    "home": "main.index",
    "pricing": "marketing.pricing",
    "shop": "shop.catalog",
    "cart": "cart.view_cart",
}


@bp.get("/<code>")
def switch_region(code):
    if code not in SUPPORTED:
        abort(404)
    endpoint = RETURN_ENDPOINTS.get(request.args.get("return", "home"), "main.index")
    response = redirect(url_for(endpoint))
    response.set_cookie("region", code, max_age=ONE_YEAR, samesite="Lax")
    return response
