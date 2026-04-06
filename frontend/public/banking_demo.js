const state = {
  userId: 'CIF000000001',
  actorRole: 'customer',
};

function setOutput(elementId, data, isError = false) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.classList.toggle('error', isError);
  if (typeof data === 'string') {
    el.textContent = data;
    return;
  }
  el.textContent = JSON.stringify(data, null, 2);
}

function buildHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    'X-User-Id': state.userId,
    'X-Actor-Role': state.actorRole,
    ...extra,
  };
}

async function callApi(path, options = {}) {
  const res = await fetch(path, options);
  const text = await res.text();
  let payload = text;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (e) {
    // Keep raw text when backend does not return JSON.
  }

  if (!res.ok) {
    throw new Error(typeof payload === 'string' ? payload : JSON.stringify(payload));
  }
  return payload;
}

function wireIdentity() {
  const btn = document.getElementById('saveIdentity');
  btn?.addEventListener('click', () => {
    const userId = document.getElementById('userId')?.value?.trim();
    const actorRole = document.getElementById('actorRole')?.value?.trim() || 'customer';

    if (!userId) {
      setOutput('queryResult', 'X-User-Id 不可為空', true);
      return;
    }

    state.userId = userId;
    state.actorRole = actorRole;
    setOutput('queryResult', {
      message: '已套用身份',
      user_id: state.userId,
      actor_role: state.actorRole,
    });
  });
}

function wireQueryActions() {
  const accountsBtn = document.getElementById('loadAccounts');
  const beneficiariesBtn = document.getElementById('loadBeneficiaries');

  accountsBtn?.addEventListener('click', async () => {
    setOutput('queryResult', '載入中...');
    try {
      const data = await callApi('/api/banking/accounts', {
        method: 'GET',
        headers: buildHeaders(),
      });
      setOutput('queryResult', data);
    } catch (err) {
      setOutput('queryResult', String(err.message || err), true);
    }
  });

  beneficiariesBtn?.addEventListener('click', async () => {
    setOutput('queryResult', '載入中...');
    try {
      const data = await callApi('/api/banking/beneficiaries', {
        method: 'GET',
        headers: buildHeaders(),
      });
      setOutput('queryResult', data);
    } catch (err) {
      setOutput('queryResult', String(err.message || err), true);
    }
  });
}

function wireBeneficiaryActions() {
  const btn = document.getElementById('createBeneficiary');
  btn?.addEventListener('click', async () => {
    const nickname = document.getElementById('beneficiaryNickname')?.value?.trim();
    const bankCode = document.getElementById('beneficiaryBankCode')?.value?.trim();
    const accountId = document.getElementById('beneficiaryAccountId')?.value?.trim();

    if (!nickname || !bankCode || !accountId) {
      setOutput('beneficiaryResult', 'nickname / bank_code / account_id 皆為必填', true);
      return;
    }

    setOutput('beneficiaryResult', '送出中...');
    try {
      const data = await callApi('/api/banking/beneficiaries', {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify({
          nickname,
          bank_code: bankCode,
          account_id: accountId,
        }),
      });
      setOutput('beneficiaryResult', data);
    } catch (err) {
      setOutput('beneficiaryResult', String(err.message || err), true);
    }
  });
}

function wireTransferActions() {
  const btn = document.getElementById('transfer');
  btn?.addEventListener('click', async () => {
    const fromAccount = document.getElementById('fromAccount')?.value?.trim();
    const toAccount = document.getElementById('toAccount')?.value?.trim();
    const amount = Number(document.getElementById('amount')?.value);
    const note = document.getElementById('transferNote')?.value?.trim() || '';
    const idempotencyKey = document.getElementById('idempotencyKey')?.value?.trim() || '';

    if (!fromAccount || !toAccount || !amount || amount <= 0) {
      setOutput('transferResult', 'from_account / to_account / amount 需為有效值', true);
      return;
    }

    setOutput('transferResult', '送出中...');
    try {
      const headers = buildHeaders(
        idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}
      );
      const data = await callApi('/api/banking/transfers', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          from_account: fromAccount,
          to_account: toAccount,
          amount,
          note,
        }),
      });
      setOutput('transferResult', data);
    } catch (err) {
      setOutput('transferResult', String(err.message || err), true);
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  wireIdentity();
  wireQueryActions();
  wireBeneficiaryActions();
  wireTransferActions();
  setOutput('queryResult', {
    message: '準備完成，請先查詢帳戶與受款人。',
    user_id: state.userId,
    actor_role: state.actorRole,
  });
});
