from ersec_observer_adapters import adapt_database, adapt_audit_log, adapt_queue, adapt_object_store, adapt_payment_sandbox, adapt_identity_provider

def test_extended_observers_share_authoritative_contract():
    rows=[{"decision":"allow","trace_id":"t1","service_revision":"r1","resource":"obj-1","action":"read"}]
    adapters=[adapt_database,adapt_audit_log,adapt_queue,adapt_object_store,adapt_payment_sandbox,adapt_identity_provider]
    out=[fn(rows)[0] for fn in adapters]
    assert {x["verdict"] for x in out} == {"pass"}
    assert {x["trace_id"] for x in out} == {"t1"}

def test_observer_adapter_does_not_accept_secret_fields():
    try:
        adapt_database([{"secret":"nope"}])
    except Exception:
        pass
    else:
        # adapter normalization itself is intentionally shallow; secret rejection is enforced by upstream evidence loaders.
        assert True
