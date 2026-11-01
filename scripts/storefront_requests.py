"""Source-derived SSR request contracts; synthetic IDs, never captured credentials."""
from __future__ import annotations
import hashlib
from urllib.parse import urlencode, quote

PRODUCT_FIELDS="*variants.calculated_price,+variants.inventory_quantity,*variants.images,*variants.options,+metadata,+tags,"
CATEGORY_FIELDS="*category_children, *products, *parent_category, *parent_category.parent_category"
CART_FIELDS="*items, *region, *items.product, *items.variant, *items.thumbnail, *items.metadata, +items.total, *promotions, +shipping_methods.name"
ORDER_FIELDS="*payment_collections.payments,*items,*items.metadata,*items.variant,*items.product"
SOURCE_FILES=('products.ts','categories.ts','collections.ts','cart.ts','orders.ts','customer.ts','fulfillment.ts','payment.ts','variants.ts','locales.ts','product-options.ts','regions.ts')

def catalog(split: str, index: int) -> list[tuple[str,dict[str,str]]]:
    suffix='01'+hashlib.sha256(f'{split}:{index}'.encode()).hexdigest()[:24].upper()
    reg='reg_'+suffix;cart='cart_'+suffix;collection='pcol_'+suffix
    limits={'train':[1,3,6,12,20,50,100],'validation':[2,7,15,25,75]}.get(split,[4,9,18,30,60])
    limit=str(limits[index%len(limits)]);offset=str(index*int(limit))
    products={'limit':limit,'offset':offset,'region_id':reg,'fields':PRODUCT_FIELDS}
    return [('/store/collections',{'fields':'id, handle, title','limit':limit,'offset':offset}),
        ('/store/collections',{'fields':'*products','limit':limit,'offset':offset}),
        ('/store/collections',{'handle':f'collection-{split}-{index}','fields':'*products'}),
        ('/store/collections/'+collection,{}),
        ('/store/product-categories',{'fields':CATEGORY_FIELDS,'limit':limit}),
        ('/store/product-categories',{'fields':'*category_children, *products','handle':f'category-{split}-{index}'}),
        ('/store/products',products),
        ('/store/products',{**products,'collection_id':collection,'fields':'*variants.calculated_price'}),
        ('/store/products',{**products,'handle':f'product-{split}-{index}'}),
        ('/store/products',{**products,'category_id[0]':'pcat_'+suffix,'order':'-created_at'}),
        ('/store/carts/'+cart,{'fields':CART_FIELDS}),
        ('/store/carts/'+cart,{'fields':'id,region_id'}),
        ('/store/orders/order_'+suffix,{'fields':ORDER_FIELDS}),
        ('/store/orders',{'limit':limit,'offset':offset,'order':'-created_at','fields':'*items,+items.metadata,*items.variant,*items.product'}),
        ('/store/customers/me',{'fields':'*orders'}),
        ('/store/shipping-options',{'cart_id':cart}),
        ('/store/payment-providers',{'region_id':reg}),
        ('/store/product-options',{'is_exclusive':'false','fields':'*values'}),
        ('/store/product-variants/variant_'+suffix,{'fields':'*images'}),
        ('/store/regions/'+reg,{}),('/store/locales',{})]

def requests(split: str,index: int) -> list[dict]:
    rows=[]
    for path,fields in catalog(split,index):
        items=list(fields.items())
        for reverse in (False,True):
            for percent in (False,True):
                query=urlencode(list(reversed(items)) if reverse else items,**({'quote_via':quote} if percent else {}))
                for headers in ({},{'content-type':'application/json'}):
                    rows.append({'method':'GET','path':path,'query':query,'headers':headers,'body':''})
    return rows
