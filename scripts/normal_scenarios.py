"""Predeclared benign scenario pools; acceptance values are never used to fit."""
from __future__ import annotations

import random
from typing import Any

POOLS = {
    'train': {
        'names': ['Alex', 'Mei', 'Ana-Maria', "O'Connor", 'Søren', '李明', 'Noah', 'Amelia'],
        'cities': ['Copenhagen', 'Aarhus', 'Odense', 'Aalborg'],
        'streets': ['Market Street', 'Harbor Road', 'Garden Lane', '北門路', "King's Road"],
        'queries': ['cotton shirt', 'blue backpack', '中文商品', 'size 10 shoes', 'linen pillow',
                    'red scarf', 'wooden desk', 'coffee cup', 'shirt & trousers', '', '100% cotton', 'summer sale'],
    },
    'validation': {
        'names': ['Léa', 'Mika', '陳安', 'Jean-Luc'],
        'cities': ['Esbjerg', 'Randers'],
        'streets': ['School Avenue', 'Station Road', '南湖路'],
        'queries': ['wool jacket', 'travel bag', 'glass bottle', '黑色外套', '2-piece set', 'gift for mum'],
    },
    'acceptance': {
        'names': ['Zoë', 'Arjun', '林語', 'Mary-Jane', 'Émile'],
        'cities': ['Roskilde', 'Kolding', 'Vejle'],
        'streets': ['Forest Crescent', 'Lake Terrace', '東海路', 'Queens Square'],
        'queries': ['ceramic bowl', 'recycled tote', 'rain coat', '保溫杯', 'A+B notebook', 'kids winter boots'],
    },
}


def profile(split: str, index: int) -> dict[str, Any]:
    pool = POOLS[split]
    rng = random.Random(f'normal-diversity-v2:{split}:{index}')
    result = {
        'first_name': pool['names'][index % len(pool['names'])],
        'last_name': pool['names'][(index // len(pool['names']) + 1) % len(pool['names'])],
        'city': rng.choice(pool['cities']),
        'address_1': f"{rng.randint(1, 250)} {rng.choice(pool['streets'])}",
        'postal_code': str(rng.randint(1000, 9999)),
        'quantity': 1 + index % 4, 'product_index': index % 4,
        'variant_index': (index // 4) % 4,
        'query': pool['queries'][index % len(pool['queries'])],
        'limit': [5, 10, 20, 30][index % 4],
        'offset': [0, 1, 2][index % 3],
    }
    if index % 3 == 0:
        result['address_2'] = ''
    elif index % 3 == 1:
        result['address_2'] = f'Apartment {1 + index % 25}'
    if index % 2:
        result['billing'] = {'address_1': f"{rng.randint(1, 250)} {rng.choice(pool['streets'])}"}
    return result
