#!/usr/bin/env python3
"""One-shot acceptance driver for the ``verify`` Compose service.

Order of operations (mirrors the acceptance contract):

1. grammar engine + storage unit tests,
2. (image build happens before this container starts -- ``compose up
   --build``),
3. HTTP smoke against the running arbiter:
   unique acceptance, ambiguous acceptance with two stable trees,
   non-consuming-cycle rejection, equivalent retransmission replay,
   audit-id conflict preserving the original evidence,
   two arbiter instances sharing one sealed volume (rolling-deploy
   duplicate seal must conflict and keep the first evidence).

Exits 0 only when every step passes; any failure exits 1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid

BASE_URL = os.environ.get("ARBITER_BASE_URL", "http://127.0.0.1:8080")
HEALTH_TIMEOUT = float(os.environ.get("HEALTH_TIMEOUT", "30"))

failures = []


def step(name):
    print(f"\n--- {name}", flush=True)


def check(cond, msg):
    if cond:
        print(f"    PASS: {msg}")
    else:
        print(f"    FAIL: {msg}")
        failures.append(msg)


def http_post(path, payload, base=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        (base or BASE_URL) + path, data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def http_get(path, base=None):
    with urllib.request.urlopen((base or BASE_URL) + path, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def wait_healthy(base=None):
    deadline = time.time() + HEALTH_TIMEOUT
    last = None
    while time.time() < deadline:
        try:
            status, body = http_get("/healthz", base=base)
            if status == 200 and body.get("status") == "ok":
                print(f"    PASS: 健康检查 200 {body}（{base or BASE_URL}）")
                return True
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.5)
    print(f"    FAIL: 健康检查超时（{HEALTH_TIMEOUT}s，{base or BASE_URL}）：{last}")
    failures.append("health")
    return False


def _docker_available():
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _sh(args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def _container_ip(cid, net):
    template = '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % net
    out = _sh(["docker", "inspect", "-f", template, cid])
    return out.stdout.strip()


def _start_shared_peers_docker(run_id):
    """Start two arbiter containers on one fresh shared volume."""
    image = "forest-arbiter:local"
    volume = f"verify-shared-{run_id}"
    network = f"verify-net-{run_id}"
    name_a, name_b = f"verify-a-{run_id}", f"verify-b-{run_id}"
    for cid in (name_a, name_b):
        _sh(["docker", "rm", "-f", cid], check=False)
    _sh(["docker", "volume", "create", volume])
    _sh(["docker", "network", "create", network], check=False)
    created = {"volume": volume, "network": network,
               "containers": [name_a, name_b]}
    try:
        for name in (name_a, name_b):
            _sh(["docker", "run", "-d", "--name", name,
                 "--network", network,
                 "-e", "ARBITER_HOST=0.0.0.0", "-e", "ARBITER_PORT=8080",
                 "-e", "ARBITER_STORE=/data/sealed.json",
                 "-v", f"{volume}:/data", image])
        ip_a = _container_ip(name_a, network)
        ip_b = _container_ip(name_b, network)
        created["base_a"] = f"http://{ip_a}:8080"
        created["base_b"] = f"http://{ip_b}:8080"
    except Exception:
        _cleanup_shared_peers_docker(created)
        raise
    return created


def _cleanup_shared_peers_docker(created):
    for cid in created.get("containers", []):
        _sh(["docker", "rm", "-f", cid], check=False)
    if created.get("network"):
        _sh(["docker", "network", "rm", created["network"]], check=False)
    if created.get("volume"):
        _sh(["docker", "volume", "rm", created["volume"]], check=False)


def _start_shared_peers_local():
    """Local fallback: two service subprocesses sharing one store file."""
    data_dir = tempfile.mkdtemp(prefix="arbiter-shared-")
    store = os.path.join(data_dir, "sealed.json")
    procs = []
    logfiles = []
    bases = []
    for port in (18081, 18082):
        log = open(os.path.join(data_dir, f"arbiter-{port}.log"), "w",
                   encoding="utf-8")
        env = dict(os.environ, ARBITER_HOST="127.0.0.1",
                   ARBITER_PORT=str(port), ARBITER_STORE=store)
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "app.service"],
            stdout=log, stderr=subprocess.STDOUT, env=env))
        logfiles.append(log)
        bases.append(f"http://127.0.0.1:{port}")
    return {"bases": bases, "procs": procs, "logs": logfiles}


def _cleanup_shared_peers_local(created):
    for proc in created.get("procs", []):
        proc.terminate()
    for proc in created.get("procs", []):
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    for log in created.get("logs", []):
        log.close()


def shared_volume_scenario(run_id):
    """Two initialized instances sharing one sealed.json must not duplicate-seal."""
    use_docker = _docker_available()
    created = None
    try:
        if use_docker:
            print("    （Docker 可用：启动共享同一数据卷的两个 arbiter 容器）")
            created = _start_shared_peers_docker(run_id)
            base_a, base_b = created["base_a"], created["base_b"]
        elif os.environ.get("ALLOW_LOCAL_FALLBACK") == "1":
            print("    （Docker 不可用：本地启动共享同一封存文件的两个子进程）")
            created = _start_shared_peers_local()
            base_a, base_b = created["bases"]
        else:
            print("    SKIP: Docker 不可用且未设置 ALLOW_LOCAL_FALLBACK=1，"
                  "跳过共享卷双实例场景")
            return

        if not wait_healthy(base_a) or not wait_healthy(base_b):
            return

        aid = f"verify-shared-{run_id}"
        first = {
            "audit_id": aid, "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        # Instance A seals the first evidence.
        status, body = http_post("/api/v1/analyze", first, base=base_a)
        check(status == 200 and body.get("seal_status") == "SEALED",
              f"实例 A 首份审计封存 SEALED（实际 HTTP {status} "
              f"{body.get('seal_status')}）")
        check(body.get("result", {}).get("production_sequence") == [1],
              "A 的结论为 S->a 派生（产生式 [1]）")

        # Instance B, sharing the volume but initialized before the seal,
        # submits semantically different evidence under the same id.
        other = {
            "audit_id": aid, "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["b"]}],
            "start": "S", "tokens": ["b"],
        }
        status, body = http_post("/api/v1/analyze", other, base=base_b)
        check(status == 409 and body.get("error") == "AUDIT_ID_CONFLICT",
              f"实例 B 同标识不同语义提交返回 AUDIT_ID_CONFLICT "
              f"（实际 HTTP {status} {body.get('error')}）")
        orig = body.get("original_evidence", {}).get("conclusion", {})
        check(orig.get("production_sequence") == [1]
              and orig.get("tree", {}).get("children", [{}])[0]
                  .get("token") == "a",
              "冲突响应回传的仍是 A 的首份证据")

        # Rereading by id from BOTH instances must keep yielding A.
        for label, base in (("A", base_a), ("B", base_b)):
            s, b = http_get(f"/api/v1/conclusion/{aid}", base=base)
            conclusion = b.get("conclusion", {})
            token = (conclusion.get("tree", {}).get("children", [{}])[0]
                     .get("token"))
            check(s == 200 and token == "a"
                  and conclusion.get("production_sequence") == [1],
                  f"从实例 {label} 重新读取仍为 A 的首份证据（token a，实际 "
                  f"HTTP {s} token={token}）")

        # B can still replay A's evidence with an equivalent submission.
        status, body = http_post("/api/v1/analyze", first, base=base_b)
        check(status == 200 and body.get("seal_status") == "REPLAYED",
              f"实例 B 语义等价重放回放 A 的证据 REPLAYED（实际 HTTP {status} "
              f"{body.get('seal_status')}）")
    finally:
        if created is not None:
            if use_docker:
                _cleanup_shared_peers_docker(created)
            else:
                _cleanup_shared_peers_local(created)


def main() -> int:
    step("步骤 1/3：文法引擎与封存存储单元测试")
    if os.environ.get("SKIP_UNIT_TESTS") == "1":
        print("    （单元测试已在本阶段之外执行，跳过）")
    else:
        loader = unittest.TestLoader()
        suite = loader.discover("tests", pattern="test_*.py")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not result.wasSuccessful():
            failures.append("unit tests")
            # Still report early; HTTP smoke is meaningless without engine.
            return report()

    if not wait_healthy():
        return report()

    run_id = uuid.uuid4().hex[:8]

    step("步骤 2/3：唯一接受场景（唯一树）")
    uid = f"verify-unique-{run_id}"
    status, body = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "start": "S",
        "tokens": ["a", "b"],
    })
    check(status == 200, f"HTTP 200（实际 {status}）")
    res = body.get("result", {})
    check(res.get("verdict") == "UNIQUE_ACCEPTED",
          f"verdict=UNIQUE_ACCEPTED（实际 {res.get('verdict')}）")
    check(res.get("production_sequence") == [1],
          f"唯一产生式序列 [1]（实际 {res.get('production_sequence')}）")
    check(body.get("seal_status") == "SEALED", "首次提交封存 SEALED")
    tree = res.get("tree", {})
    check(tree.get("symbol") == "S" and tree.get("span") == [0, 2]
          and len(tree.get("children", [])) == 2,
          "返回唯一派生树且跨度覆盖全部词元")

    # Equivalent retransmission (declaration order shuffled) -> replay.
    status2, body2 = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "start": "S",
        "tokens": ["a", "b"],
    })
    check(status2 == 200 and body2.get("seal_status") == "REPLAYED",
          f"语义等价重放回封存结论 REPLAYED（实际 HTTP {status2} {body2.get('seal_status')}）")
    check(body2.get("result", {}).get("production_sequence") == [1],
          "回放的证据与原结论一致")

    # Same audit id, different input -> 409 conflict, evidence retained.
    status3, body3 = http_post("/api/v1/analyze", {
        "audit_id": uid,
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
        "start": "S",
        "tokens": ["a"],
    })
    check(status3 == 409 and body3.get("error") == "AUDIT_ID_CONFLICT",
          f"同标识不同输入冲突 HTTP 409（实际 {status3}）")
    orig = body3.get("original_evidence", {}).get("conclusion", {})
    check(orig.get("verdict") == "UNIQUE_ACCEPTED"
          and orig.get("production_sequence") == [1],
          "冲突响应保留并回传原始证据")

    step("步骤 3a：歧义接受场景（两棵按编号序列稳定选出的树）")
    aid = f"verify-amb-{run_id}"
    status, body = http_post("/api/v1/analyze", {
        "audit_id": aid,
        "nonterminals": ["E"],
        "productions": [
            {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
            {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
            {"id": 3, "lhs": "E", "rhs": ["id"]},
        ],
        "start": "E",
        "tokens": ["id", "+", "id", "*", "id"],
    })
    res = body.get("result", {})
    check(status == 200 and res.get("verdict") == "AMBIGUOUS_ACCEPTED",
          f"歧义接受（实际 HTTP {status} {res.get('verdict')}）")
    seqs = res.get("production_sequences", {})
    s1, s2 = seqs.get("first"), seqs.get("second")
    check(isinstance(s1, list) and isinstance(s2, list) and s1 != s2,
          f"两棵树产生式序列不同：{s1} vs {s2}")
    check(s1 == sorted([s1, s2])[0],
          f"first 为编号序列字典序最小：{s1} <= {s2}")
    first, second = res.get("trees", {}).values() if res.get("trees") else ({}, {})
    check(first.get("span") == [0, 5] and second.get("span") == [0, 5],
          "两棵不同派生树均完整覆盖输入 [0,5]")
    # Determinism: re-submit under a new id and compare tree sequences.
    status_b, body_b = http_post("/api/v1/analyze", {
        "audit_id": f"verify-amb2-{run_id}",
        "nonterminals": ["E"],
        "productions": [
            {"id": 3, "lhs": "E", "rhs": ["id"]},
            {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
            {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
        ],
        "start": "E",
        "tokens": ["id", "+", "id", "*", "id"],
    })
    sb = body_b.get("result", {}).get("production_sequences", {})
    check(sb.get("first") == s1 and sb.get("second") == s2,
          f"产生式提交顺序打乱后选树仍稳定：{sb.get('first')} == {s1}")

    step("步骤 3b：可达不消费词元循环必须明确拒绝")
    cid = f"verify-cycle-{run_id}"
    status, body = http_post("/api/v1/analyze", {
        "audit_id": cid,
        "nonterminals": ["A", "B"],
        "productions": [
            {"id": 1, "lhs": "A", "rhs": ["B"]},
            {"id": 2, "lhs": "B", "rhs": ["A"]},
            {"id": 3, "lhs": "A", "rhs": []},
        ],
        "start": "A",
        "tokens": [],
    })
    res = body.get("result", {})
    rej = res.get("rejection", {})
    check(status == 200 and res.get("verdict") == "REJECTED",
          f"循环场景 REJECTED（实际 HTTP {status} {res.get('verdict')}）")
    check(rej.get("reason") == "NONCONSUMING_CYCLE",
          f"原因为 NONCONSUMING_CYCLE（实际 {rej.get('reason')}）")
    cyc = rej.get("evidence", {}).get("cycle")
    check(cyc == ["A", "B", "A"], f"给出循环证据 {cyc}")
    check("无限" in rej.get("detail", "") or "循环" in rej.get("detail", ""),
          "给出首个可操作中文原因")

    step("步骤 4：共享封存卷的两个实例不得重复封存（首份证据优先）")
    shared_volume_scenario(run_id)

    return report()


def report() -> int:
    print("\n================ 验收汇总 ================")
    if failures:
        print(f"失败 {len(failures)} 项：")
        for f in failures:
            print(f"  - {f}")
        print("RESULT: FAIL")
        return 1
    print("全部步骤通过：单元测试 / 镜像 / 唯一 / 歧义 / 无消费环 / 回放 / "
          "冲突 / 共享卷双实例首份证据优先")
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
