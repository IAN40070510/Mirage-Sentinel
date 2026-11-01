from pathlib import Path
from scripts.storefront_requests import PRODUCT_FIELDS, CATEGORY_FIELDS, CART_FIELDS, ORDER_FIELDS

def test_catalog_field_lists_match_actual_storefront_source() -> None:
    root=Path(__file__).resolve().parents[1]/'commerce/apps/storefront/src/lib/data'
    for name,value in [('products.ts',PRODUCT_FIELDS),('categories.ts',CATEGORY_FIELDS),('cart.ts',CART_FIELDS),('orders.ts',ORDER_FIELDS)]:
        assert value in (root/name).read_text(encoding='utf-8')
