from commerce_ml.data import Record, audit_splits, digest, near_key


def row(identifier: str, text: str, label: int = 0, session: str | None = None) -> Record:
    return Record(identifier, text, label, 'external', session, None, False, digest(text), near_key(text))


def test_normal_template_exception_is_explicit_and_does_not_allow_exact_duplicates():
    splits = {'train': [row('a', 'POST /cart {"quantity":1}', session='s1')],
              'test': [row('b', 'POST /cart {"quantity":2}', session='s2')]}
    assert audit_splits(splits)['cross_split_conflicts']
    audit = audit_splits(splits, allow_shared_normal_templates=True)
    assert not audit['cross_split_conflicts']
    assert audit['shared_normal_template_rows'] == {'train/test': 1}
    splits['test'] = [row('b', splits['train'][0].text, session='s2')]
    assert 'train/test:exact' in audit_splits(splits, allow_shared_normal_templates=True)['cross_split_conflicts']


def test_attack_overlap_and_shared_sessions_still_block():
    splits = {'train': [row('a', 'POST /cart {"quantity":1}', session='s1')],
              'test': [row('b', 'POST /cart {"quantity":2}', label=1, session='s2')]}
    assert 'train/test:near' in audit_splits(splits, allow_shared_normal_templates=True)['cross_split_conflicts']
    splits['test'] = [row('b', 'POST /cart {"quantity":2}', session='s1')]
    assert 'train/test:session' in audit_splits(splits, allow_shared_normal_templates=True)['cross_split_conflicts']
