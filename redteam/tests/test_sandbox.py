from redteam.sandbox import Sandbox


def test_valid_sandbox() -> None:
    s = Sandbox(
        isolation="box",
        device="box-01",
        egress_allowlist=["replica.internal"],
        replica_seed="fake-v1",
    )
    assert s.validate() == []


def test_rejects_mig() -> None:
    s = Sandbox(isolation="mig", device="gpu-0", egress_allowlist=["r"], replica_seed="s")
    assert any("MIG" in p for p in s.validate())


def test_requires_egress_allowlist() -> None:
    s = Sandbox(isolation="card", device="gpu-0", egress_allowlist=[], replica_seed="s")
    assert any("egress allowlist" in p for p in s.validate())


def test_requires_device_and_seed() -> None:
    s = Sandbox()
    problems = s.validate()
    assert any("device/box" in p for p in problems)
    assert any("replica seed" in p for p in problems)
