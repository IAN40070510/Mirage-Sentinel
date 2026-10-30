import numpy as np

from commerce_ml.data import Record, digest, near_key
from commerce_ml.normal_balance import normal_route_group
from commerce_ml.train import choose_threshold, weights


def record(index: int, path: str, label: int = 0) -> Record:
    text = 'GET\n' + path + '\nq=' + str(index)
    return Record(str(index), text, label, 'external', None, None, False, digest(text), near_key(text))


def test_many_product_rows_do_not_outweigh_checkout_route():
    rows = [record(i, '/store/products') for i in range(100)]
    rows += [record(100, '/store/carts/cart_123/complete')]
    rows += [record(100 + label, '/store/products', label) for label in range(1, 5)]
    result = weights(rows, balance_normal_routes=True)
    assert np.isclose(result[:100].sum(), result[100])
    assert np.isclose(result[:101].sum(), result[101])
    assert normal_route_group('GET\n/_next/static/random.js\n') == 'GET /_next/static/*'


def test_route_fpr_constraint_prevents_hiding_a_rare_normal_failure():
    y = np.asarray([0] * 100 + [0, 1])
    pnormal = np.asarray([.99] * 100 + [.3, .2])
    probs = np.column_stack((pnormal, 1 - pnormal, np.zeros((102, 3))))
    threshold, selection = choose_threshold(y, probs, .01, ['common'] * 100 + ['checkout', 'attack'])
    assert threshold > .7
    assert selection['normal_route_fpr_constraint']


def test_real_medusa_payment_ids_and_fixture_ids_are_one_group():
    assert normal_route_group('POST\n/store/payment-collections/pay_col_ABC/payment-sessions\n') == normal_route_group('POST\n/store/payment-collections/pay_col_XYZ/payment-sessions\n')
    assert normal_route_group('POST\n/store/carts/<ID>/line-items\n') == normal_route_group('POST\n/store/carts/cart_ABC/line-items\n')
