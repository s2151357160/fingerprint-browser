"""fingerprint_browser 测试套件（零依赖，12308 同款风格）

运行:  python test_all.py   （在项目根目录或任意位置均可）
覆盖:
  1. fp_reputation.score_of 全评分分支
  2. ReputationStore: preferred_names / same_country_names / node_country
     / get / get_score / summary / update→save→重载持久化
  3. 死代码自检: AST 扫描全项目（防"方法被吞"类 bug 复发）
  4. 全模块编译检查
"""
import ast
import py_compile
import sys
import tempfile
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_DIR.parent))

from fingerprint_browser.fp_reputation import ReputationStore, score_of

PASS = 0
FAIL = 0


def check(cond, desc):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  ✗ FAIL: {desc}")


def section(name):
    print(f"\n== {name} ==")


# ── 1. score_of 评分分支 ─────────────────────────────────────────
section("T1 score_of 评分分支")
check(score_of({"proxy": True}) == 0, "代理标记 → 0")
check(score_of({"proxy": True, "mobile": True}) == 0, "proxy 优先于 mobile")
check(score_of({"mobile": True}) == 3, "移动网络 → 3")
check(score_of({"hosting": True}) == 1, "数据中心(hosting) → 1")
check(score_of({"as": "AS16509 Amazon Technologies"}) == 1, "ASN 关键词兜底 → 1")
check(score_of({"as": "AS4134 Chinanet"}) == 2, "家宽(无标记) → 2")
check(score_of({}) == 2, "空信息按家宽 → 2")

# ── 2-6. ReputationStore ─────────────────────────────────────────
DATA = {
    "A": {"score": 2, "latency_ms": 300, "country": "JP", "city": "Tokyo",
          "checked_at": "2026-10-14 10:00:00"},
    "B": {"score": 3, "latency_ms": None, "country": "US", "city": "NYC",
          "checked_at": "2026-10-14 10:00:01"},
    "C": {"score": 1, "latency_ms": 100, "country": "JP", "city": "Osaka",
          "checked_at": "2026-10-14 10:00:02"},
    "D": {"score": 2, "latency_ms": 900, "country": "JP", "city": "",
          "checked_at": "2026-10-14 10:00:03"},
    "E": {"score": -1, "latency_ms": None, "country": "", "city": "",
          "checked_at": ""},
    "F": {"score": 0, "latency_ms": 100, "country": "CN", "city": "Beijing",
          "checked_at": "2026-10-14 10:00:04"},
}
NAMES = list(DATA)


def fresh_store(path):
    s = ReputationStore(path=path)
    s._data = dict(DATA)
    return s


tmpdir = Path(tempfile.mkdtemp())

section("T2 preferred_names（信誉+延迟过滤）")
s = fresh_store(tmpdir / "t2.json")
check(s.preferred_names(NAMES) == ["A", "B"], "住宅+移动入选, 数据中心/代理/未扫描/高延迟排除")
check(s.preferred_names([]) == [], "空池返回空")
check(s.preferred_names(["E", "F", "C"]) == [], "全不合格返回空")
check(hasattr(ReputationStore, "preferred_names"), "方法真实存在于类")

section("T3 same_country_names（同国过滤）")
check(s.same_country_names(NAMES, "jp") == ["A", "C", "D"], "小写匹配大写数据")
check(s.same_country_names(NAMES, "JP") == ["A", "C", "D"], "大写匹配")
check(s.same_country_names(NAMES, "cn") == ["F"], "CN 只含已扫描的 F")
check(s.same_country_names(NAMES, "DE") == [], "无匹配国家返回空")
check(s.same_country_names(NAMES, "") == [], "空国家参数不误配 E(未扫描)")

section("T4 node_country / get / get_score")
check(s.node_country("A") == ("JP", "Tokyo"), "node_country 返回 (国家码, 城市)")
check(s.node_country("E") == (None, None), "未扫描节点返回 (None, None)")
check(s.get("A") == DATA["A"], "get 返回原始记录")
check(s.get("Z9") is None, "get 未知节点返回 None")
check(s.get_score("F") == 0, "get_score 代理=0")
check(s.get_score("E") == -1, "get_score 未扫描=-1")
check(s.get_score("Z9") == -1, "get_score 未知节点=-1")

section("T5 summary（分布统计）")
sm = s.summary()
check(sm["count"] == 6, "count=6")
check(sm["distribution"]["3"] == 1, "移动 1 个")
check(sm["distribution"]["2"] == 2, "住宅 2 个")
check(sm["distribution"]["1"] == 1, "数据中心 1 个")
check(sm["distribution"]["0"] == 1, "代理 1 个")
check(sm["distribution"]["unknown"] == 1, "未扫描 1 个")
check(sm["avg_latency_ms"] == 350, "平均延迟 (300+100+900+100)/4=350")
check(sm["min_latency_ms"] == 100, "最低延迟 100")

section("T6 update → save → 重载持久化")
s2 = fresh_store(tmpdir / "t6.json")
s2.update({"G": {"score": 3, "latency_ms": 40, "country": "JP", "city": "",
                 "checked_at": "2026-10-14 12:00:00"}})
s3 = ReputationStore(path=tmpdir / "t6.json")
check(s3.get("G") is not None, "重载后新节点 G 在")
check(s3.get_score("G") == 3, "重载后 G 评分=3")
check(s3.get("A") is not None, "重载后原有节点 A 也在")
check(s3.preferred_names(["G", "C"]) == ["G"], "重载后过滤逻辑正常")

# ── 7. 死代码自检 ────────────────────────────────────────────────
section("T7 死代码自检（防 preferred_names 类 bug 复发）")


def find_dead_code(path: Path):
    issues = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for i, stmt in enumerate(node.body):
                if isinstance(stmt, ast.Return):
                    meaningful = [x for x in node.body[i + 1:]
                                  if not (isinstance(x, ast.Expr)
                                          and isinstance(x.value, ast.Constant))]
                    if meaningful:
                        issues.append(f"{path.name}:{meaningful[0].lineno} "
                                      f"函数 {node.name!r} return 后有不可达语句")
                    break
    return issues


py_files = sorted(PROJECT_DIR.rglob("*.py"))
dead = []
for f in py_files:
    if "__pycache__" in f.parts:
        continue
    dead.extend(find_dead_code(f))
check(len(py_files) >= 16, f"扫描覆盖全部模块（{len(py_files)} 个文件）")
check(dead == [], f"死代码应为 0，实际: {dead or '0 处'}")

# ── 8. 全模块编译检查 ────────────────────────────────────────────
section("T8 全模块编译检查")
errs = []
for f in py_files:
    if "__pycache__" in f.parts or f.name == "test_all.py":
        continue
    try:
        py_compile.compile(str(f), doraise=True)
    except py_compile.PyCompileError as e:
        errs.append(f"{f.name}: {e}")
check(errs == [], f"编译错误应为 0，实际: {errs or '0 处'}")

# ── 结果 ─────────────────────────────────────────────────────────
print(f"\n{'=' * 40}")
print(f"结果: {PASS} 通过, {FAIL} 失败")
sys.exit(1 if FAIL else 0)