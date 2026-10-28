from scripts.normal_scenarios import POOLS, profile


def test_acceptance_values_are_reserved_and_scenarios_vary():
    for field in ('names', 'cities', 'streets', 'queries'):
        development = set(POOLS['train'][field]) | set(POOLS['validation'][field])
        assert development.isdisjoint(POOLS['acceptance'][field])
    cases = [profile('train', i) for i in range(160)]
    assert {p['quantity'] for p in cases} == {1, 2, 3, 4}
    assert len({p['first_name'] for p in cases}) == 8
    assert len({p['address_1'] for p in cases}) > 100
    assert any(p.get('address_2') == '' for p in cases)
    assert any(p.get('billing') for p in cases)
    assert any(not p.get('billing') for p in cases)
    assert profile('acceptance', 8) == profile('acceptance', 8)
