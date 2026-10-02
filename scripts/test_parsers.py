#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单元自测: 全协议解析器 + sing-box check 配置合法性 + 分类逻辑"""
import os, sys, json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main_v2 as mv

BASEDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 与 main_v2 运行时同一内核; 按平台选择候选路径并逐个 exists 探测
if os.name == "nt":
    _SB_CANDIDATES = [
        os.path.join(BASEDIR, "runtime", "sing-box.exe"),
        os.path.join(BASEDIR, ".sb-probe", "sing-box.exe"),
    ]
else:
    _SB_CANDIDATES = [
        os.path.join(BASEDIR, "runtime", "sing-box"),
        os.path.join(BASEDIR, "runtime", "singbox"),
    ]
SB = next((p for p in _SB_CANDIDATES if os.path.exists(p)), None)

# ══════════ 测试样本 (覆盖用户全部协议) ══════════
SAMPLES = {
    # VLESS + Reality + Vision (最高误杀率的协议组合)
    "vless_reality_vision": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=0123abcd&type=tcp#TestVlessReality",
    # VLESS + WS + TLS (CDN 中转常见)
    "vless_ws_tls": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@cdn.example.com:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws#TestVlessWs",
    # VLESS + grpc
    "vless_grpc": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=grpc-svc#TestVlessGrpc",
    # VLESS + httpupgrade
    "vless_httpupgrade": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:80?encryption=none&security=none&type=httpupgrade&path=%2Fupgrade&host=example.com#TestVlessHU",
    # VLESS + h2
    "vless_h2": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&sni=example.com&type=h2&path=%2Fh2path&host=h2.example.com#TestVlessH2",
    # VMess (ws + tls)
    "vmess_ws": "vmess://" + mv.base64.b64encode(json.dumps({
        "v": "2", "ps": "TestVmess", "add": "vm.example.com", "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
        "scy": "auto", "net": "ws", "type": "none", "host": "vm.example.com",
        "path": "/vmws", "tls": "tls", "sni": "vm.example.com"}).encode()).decode(),
    # VMess legacy (tcp, no tls, aid>0)
    "vmess_legacy": "vmess://" + mv.base64.b64encode(json.dumps({
        "v": "2", "ps": "TestVmessLegacy", "add": "legacy.example.com", "port": "8080",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "64",
        "scy": "auto", "net": "tcp", "type": "none", "tls": ""}).encode()).decode(),
    # VMess grpc
    "vmess_grpc": "vmess://" + mv.base64.b64encode(json.dumps({
        "v": "2", "ps": "TestVmessGrpc", "add": "grpc.example.com", "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
        "scy": "auto", "net": "grpc", "path": "grpc-svc", "tls": "tls"}).encode()).decode(),
    # Trojan (sni + allowInsecure)
    "trojan": "trojan://pass%40word123@example.com:443?sni=www.example.com&allowInsecure=1&type=tcp#TestTrojan",
    # Trojan ws
    "trojan_ws": "trojan://pass123@example.com:443?sni=example.com&type=ws&path=%2Ftjws&host=example.com#TestTrojanWs",
    # SS SIP002 (明文 userinfo)
    "ss_sip002": "ss://aes-256-gcm:cGFzc3dvcmQ%3D@ss.example.com:8388#TestSS",
    # SS legacy base64
    "ss_legacy": "ss://" + mv.base64.urlsafe_b64encode(b"aes-256-gcm:pass123").decode().rstrip("=") + "@legacy-ss.example.com:8388#TestSSLegacy",
    # SS 2022 (密钥格式)
    "ss_2022": "ss://2022-blake3-aes-128-gcm:8J3gp0S5y2X0YVpDZH2YvA%3D%3D@ss2022.example.com:8388#TestSS2022",
    # Hysteria2 (sni + insecure + obfs)
    "hy2": "hy2://pass123@hy2.example.com:443?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=obfspw#TestHy2",
    # Hysteria2 端口跳跃 (mport 区间+单端口混合)
    "hy2_hop": "hysteria2://pass123@hop.example.com:443?sni=hop.example.com&insecure=1&mport=2087-2097,443#TestHy2Hop",
    # Hysteria2 端口跳跃: 纯区间 (生产实际最常见的形态)
    "hy2_hop_range": "hysteria2://pass123@hop-range.example.com:443?sni=hop-range.example.com&insecure=1&mport=2087-2097#TestHy2HopRange",
    # Hysteria2 端口跳跃: 裸单端口 mport (必须归一化成 "443:443", 否则 sing-box FATAL)
    "hy2_hop_single": "hysteria2://pass123@hop-single.example.com:443?sni=hop-single.example.com&insecure=1&mport=443#TestHy2HopSingle",
    # Hysteria2 端口跳跃: 多跳列表 (两区间 + 一单端口, 共 3 跳)
    "hy2_hop_multi": "hysteria2://pass123@hop-multi.example.com:443?sni=hop-multi.example.com&insecure=1&mport=2087-2097,2080-2085,443#TestHy2HopMulti",
    # TUIC v5
    "tuic": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass123@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com&allow_insecure=1#TestTuic",
    # TUIC 密码含裸 "@": 旧正则 [^@#/?]+ 无法跨 @ → 整条被丢。实测 sing-box 对 password
    # 是"不透明字符串", 含 @ 的密码 check PASS → 应当接受 (以最后一个 @ 为锚点分割)
    "tuic_pw_at": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pa@ss@tuic-at.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic-at.example.com",
    # TUIC 密码含裸 "/": outbound_to_v2ray_link 用 urllib quote() 导出时 "/" 不转义 (safe="/"),
    # 旧解析器读不回自己导出的链接 → 导出→再解析断链 (阶段4 曾实测 roundtrip None)
    "tuic_pw_slash": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pa/ss@tuic-slash.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic-slash.example.com",
    # TUIC 密码 percent-encoded (%40/%2F): 阶段1 一直能解析, 但阶段4 导出 round-trip 曾经断链
    "tuic_pw_pct": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pa%40ss%2Fword@tuic-pct.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic-pct.example.com",
    # TUIC 密码含裸 "?": 旧正则 [^@#/?]+ 无法跨 ? → 整条被丢; 导出端 quote() 会转义成 %3F, check PASS
    "tuic_pw_question": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pa?ss@tuic-q.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic-q.example.com",
    # TUIC 无密码形态: 实测 sing-box 1.14 的 tuic outbound 对 password 是可选项
    # (空串/缺省/null 均 check PASS; 反而 uuid 必须是合法 UUID), 故接受并落为空串
    "tuic_no_pw": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811@tuic-nopw.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic-nopw.example.com",
    # AnyTLS
    "anytls": "anytls://pass123@anytls.example.com:443?sni=anytls.example.com&insecure=1#TestAnytls",
    # IPv6 字面量 (旧版正则必死的场景)
    "vless_ipv6": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443?encryption=none&security=tls&sni=v6.example.com&type=tcp#TestIPv6",
    # 域名含端口非常规 (解析应成功)
    "vless_path_edge": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:8443?encryption=none&security=none&type=ws&path=%2Fed#TestEdge",
}

# 端口跳跃样本 → 期望 server_ports (钉死归一化: 单端口必须变 "p:p", 区间与反序区间原样保留)
HOP_EXPECT = {
    "hy2_hop":        ["2087:2097", "443:443"],
    "hy2_hop_range":  ["2087:2097"],
    "hy2_hop_single": ["443:443"],
    "hy2_hop_multi":  ["2087:2097", "2080:2085", "443:443"],
}

FAIL = []
# 显式豁免才允许存在的"未校验项"。绝不允许被当成通过出现在结论里。
SKIPPED = []

# 阶段2: 缺内核时的修复指引 (与 workflow 的 Prepare sing-box runtime 步骤同一条路径)
_SB_FIX_CMD = 'python -c "import sys; sys.path.insert(0, \'scripts\'); import main_v2; main_v2.setup_environment()"'

# 阶段3 置信度档位断言 —— 取值逐条读自 main_v2.classify_network_type (未改动 main_v2):
#   cdn         = 100 (Cloudflare 段) / 95 (附加 CDN 段)
#   datacenter  = 90 (ip-api hosting) / 88 (ip-api proxy) / 80 (IDC ASN) / 70 (IDC 名称)
#   residential = 82 (家宽 ASN) / 70 (家宽名称) / 60 (rDNS 名称)
#   unknown     = 30 (全不命中) / 0 (IP 非法)
# 阶段3 桩掉 get_rdns, 故 60 档在该阶段不可达; 下界取 65 是为了同时挡住"档位塌到 rDNS
# 兜底 60 / unknown 兜底 30", 并给各类型最低合法档位留 5 档余量 (95 / 70 / 70)。
# unknown 只取上界才有意义 —— 合法值仅 30。
CONF_BANDS = {
    #         期望 net_type : (conf 下界, conf 上界)
    "cdn":         (90, 100),
    "datacenter":  (65, 90),
    "residential": (65, 82),
    "unknown":     (0, 30),
}

def run_test():
    print("=" * 70)
    print(f"阶段1: 协议解析器单元测试 ({len(SAMPLES)} 个样本)")
    print("=" * 70)
    outbounds = {}
    for name, uri in SAMPLES.items():
        parsed = mv.parse_node_uri(uri)
        if not parsed:
            FAIL.append(f"[PARSE-FAIL] {name}: {uri[:60]}")
            print(f"  ❌ {name}: 解析失败")
            continue
        ob, server, port, proto = parsed
        # 出口必备字段 (端口跳跃节点: server_port 被 server_ports 替代)
        if ob.get("server_port") is not None:
            assert ob["server"] == server and ob["server_port"] == port
        else:
            assert ob.get("server_ports"), "既无 server_port 也无 server_ports"
        outbounds[name] = ob
        print(f"  ✅ {name}: {proto} @ {server}:{port}")
        # 额外结构断言
        if name == "vless_reality_vision":
            assert ob.get("flow") == "xtls-rprx-vision", "flow 丢失"
            assert ob["tls"]["reality"]["public_key"], "reality pbk 丢失"
            assert ob["tls"]["utls"]["fingerprint"] == "chrome", "utls fp 丢失"
        if name in HOP_EXPECT:
            assert ob.get("server_ports") == HOP_EXPECT[name], \
                f"mport 归一化漂移: 期望 {HOP_EXPECT[name]} 实得 {ob.get('server_ports')}"
            # 实测约束: 不能有裸单端口
            for p in ob["server_ports"]:
                assert ":" in p, f"裸单端口 {p} 会导致 sing-box FATAL"
        if name == "tuic":
            assert ob.get("uuid") and ob.get("password") and ob.get("congestion_control")
        if name == "tuic_pw_at":
            assert ob.get("password") == "pa@ss", "密码内裸 @ 未按最后一个 @ 分割"
        if name == "tuic_pw_slash":
            assert ob.get("password") == "pa/ss", "密码内裸 / 丢失 (导出端 quote() 不转义 /)"
        if name == "tuic_pw_pct":
            assert ob.get("password") == "pa@ss/word", "percent-encoded 密码解码异常"
        if name == "tuic_no_pw":
            assert ob.get("password") == "", "无密码形态应落为空串 (实测 sing-box check PASS)"
        if name == "anytls":
            assert ob.get("password") and ob["tls"]["enabled"]

    print()
    print("=" * 70)
    print(f"阶段2: sing-box check 配置合法性 ({len(outbounds)} 个 outbound)")
    print("=" * 70)
    if not SB:
        why = (f"未找到 sing-box 二进制 → {len(outbounds)} 份 outbound 的配置合法性"
               f"**完全未经内核校验** (已探测: {', '.join(_SB_CANDIDATES)})。"
               f"修复: {_SB_FIX_CMD} (CI 侧已内建为 Prepare sing-box runtime 步骤); "
               f"显式豁免: SKIP_SINGBOX_CHECK=1")
        if os.environ.get("SKIP_SINGBOX_CHECK"):
            SKIPPED.append(f"[STAGE2] {why}")
            print(f"  ⚠️ 已豁免 (SKIP_SINGBOX_CHECK 已设置): {why}")
        else:
            FAIL.append(f"[STAGE2] {why}")
            print(f"  ❌ 未校验: {why}")
    else:
        import subprocess, tempfile
        for name, ob in outbounds.items():
            cfg = mv.build_test_config(ob, 53000 + (hash(name) % 500))
            # 清理测试用多余字段 (domain_strategy 等不存在)
            try:
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                    json.dump(cfg, f)
                    path = f.name
                r = subprocess.run([SB, "check", "-c", path], capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    print(f"  ✅ {name}: check PASS")
                else:
                    err = (r.stderr or r.stdout or "").strip().splitlines()
                    err_short = err[-1][:100] if err else "?"
                    FAIL.append(f"[CHECK-FAIL] {name}: {err_short}")
                    print(f"  ❌ {name}: check FAIL → {err_short}")
            finally:
                try:
                    os.remove(path)
                except Exception:
                    pass

    print()
    print("=" * 70)
    print("阶段3: 网络类型分类逻辑 (离线, rDNS 已打桩)")
    print("=" * 70)
    cases = [
        # (ip, asn, org, 期望 net_type)
        ("104.16.1.1", 13335, "cloudflare", "cdn"),             # CF 段硬判
        ("172.67.10.1", 13335, "Cloudflare, Inc.", "cdn"),
        ("8.8.8.8", 15169, "Google LLC", "cdn"),                 # Google 公共 DNS 段
        ("23.94.10.1", 36352, "ColoCrossing", "datacenter"),    # IDC 名称关键词 (命中 colo)
        ("211.72.35.1", 3462, "Chunghwa Telecom", "residential"),# 台湾中华电信家宽
        ("61.220.50.1", 3462, "CHT", "residential"),
        ("219.85.10.1", 17676, "Softbank BB", "residential"),   # 日本软银家宽
        ("81.19.66.1", 6679, "Skynet", "unknown"),               # 无明显特征 → 必须落 unknown
    ]
    # 离线化: classify_network_type 第 5 步会做实时 rDNS 反查 (main_v2.get_rdns →
    # socket.gethostbyaddr), 结果随运行机解析器而变 —— 81.19.66.1 正是唯一走到该步的样本。
    # 打桩后本阶段既不联网也可重复; 桩作用域仅限本 try 块, 阶段5 的 get_rdns 检查不受影响。
    _orig_rdns = mv.get_rdns
    _rdns_calls = []
    def _rdns_stub(ip):
        _rdns_calls.append(ip)
        return ""
    mv.get_rdns = _rdns_stub
    try:
        for ip, asn, org, expect in cases:
            got, conf = mv.classify_network_type(ip, None, asn, org, None)
            lo, hi = CONF_BANDS[expect]
            ok_type, ok_conf = got == expect, lo <= conf <= hi
            if not ok_type:
                FAIL.append(f"[CLASSIFY] {ip} {org}: 期望 {expect} 实得 {got}")
            if not ok_conf:
                FAIL.append(f"[CLASSIFY-CONF] {ip} {org}: 期望 {expect} 档位 {lo}~{hi} 实得 conf={conf}")
            mark = "✅" if ok_type and ok_conf else "❌"
            print(f"  {mark} {ip} ({org}) → {got} conf={conf} [档位 {lo}~{hi}]")
    finally:
        mv.get_rdns = _orig_rdns
    assert mv.get_rdns is _orig_rdns, "rDNS 桩未还原"
    # 桩被触发的样本必须恰好只有 81.19.66.1 —— 那是唯一走不到四层判据、必定落到
    # main_v2.classify_network_type 第 5 步 (源码 2079 行) 的样本。真实 get_rdns 会在该
    # 步起线程做 socket.gethostbyaddr, 桩把它换成常量 "" → 本阶段零 DNS I/O 且可重复。
    # 若日后有"自信"的样本也开始走 rDNS 兜底, 这条即报警。
    # 记进 FAIL 而非 assert: 本套件靠收集 FAIL 后统一汇报, 中途抛异常会连带吞掉
    # 阶段4/5 与失败清单, 反而看不出真正的错在哪。
    if _rdns_calls != ["81.19.66.1"]:
        FAIL.append(f"[CLASSIFY-RDNS] rDNS 兜底被非预期样本触发: {_rdns_calls} (期望恰为 ['81.19.66.1'])")
        print(f"  ❌ rDNS 兜底样本集合异常: {_rdns_calls}")
    else:
        print(f"  (rDNS 兜底仅被 {_rdns_calls} 触发 — 该调用已由桩截断, 本阶段零 DNS I/O)")

    print()
    print("=" * 70)
    print(f"阶段4: 导出器回归测试 ({len(outbounds)} 个 outbound → clash/v2ray/singbox)")
    print("=" * 70)
    for name, ob in outbounds.items():
        tag = "Test-" + name
        try:
            link = mv.outbound_to_v2ray_link(dict(ob), tag)
            if not link:
                FAIL.append(f"[EXPORT-EMPTY] {name}: v2ray 导出为空")
                print(f"  ❌ {name}: v2ray 导出为空")
                continue
            reparsed = mv.parse_node_uri(link)
            if not reparsed:
                FAIL.append(f"[EXPORT-ROUNDTRIP] {name}: 导出后无法再解析")
                print(f"  ❌ {name}: 导出 roundtrip 失败")
                continue
            _, rsrv, rport, rproto = reparsed
            assert rproto == ob["type"], f"协议漂移 {ob['type']}→{rproto}"
            assert rsrv == ob["server"], f"server 漂移 {ob['server']}→{rsrv}"
            exp_port = ob.get("server_port") or int(str(ob["server_ports"][0]).split(":")[0])
            assert rport == exp_port, f"port 漂移 {exp_port}→{rport}"
            cp = mv.outbound_to_clash(dict(ob), tag)
            if not cp or cp.get("server") != ob["server"] or not cp.get("port"):
                FAIL.append(f"[EXPORT-CLASH] {name}: clash 导出缺字段/崩溃")
                print(f"  ❌ {name}: clash 导出异常")
                continue
            sb = mv.outbound_to_singbox(dict(ob), tag)
            assert sb.get("tag") == tag, "singbox tag 丢失"
            if name in HOP_EXPECT:
                assert cp.get("ports"), "mport ports 丢失"
                assert reparsed[0].get("server_ports") == ob.get("server_ports"), \
                    f"跳跃列表 roundtrip 漂移: {ob.get('server_ports')} → {reparsed[0].get('server_ports')}"
            print(f"  ✅ {name}: roundtrip OK ({rproto} {rsrv}:{rport})")
        except Exception as e:
            FAIL.append(f"[EXPORT-EXC] {name}: {type(e).__name__} {str(e)[:80]}")
            print(f"  ❌ {name}: 异常 {type(e).__name__}")

    print()
    print("=" * 70)
    print("阶段5: 结构化源 + P2 回归测试")
    print("=" * 70)
    CLASH_SAMPLES = {
        "clash_vless_ws": {"type": "vless", "server": "cdn.example.com", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": True, "servername": "cdn.example.com",
            "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example.com"}}},
        "clash_trojan_ws": {"type": "trojan", "server": "tj.example.com", "port": 443, "password": "pw",
            "sni": "tj.example.com", "network": "ws",
            "ws-opts": {"path": "/tj", "headers": {"Host": "tj.example.com"}}},
        "clash_hy2_hop": {"type": "hysteria2", "server": "hop.example.com", "port": 443, "password": "pw",
            "sni": "hop.example.com", "ports": "2087-2097,443"},
        "clash_tuic": {"type": "tuic", "server": "tuic.example.com", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "pw", "sni": "tuic.example.com"},
        "clash_ss": {"type": "ss", "server": "ss.example.com", "port": 8388,
            "cipher": "aes-256-gcm", "password": "pw"},
        "clash_vmess": {"type": "vmess", "server": "vm.example.com", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0, "cipher": "auto",
            "tls": True, "servername": "vm.example.com", "network": "ws",
            "ws-opts": {"path": "/vm", "headers": {"Host": "vm.example.com"}}},
    }
    for name, p in CLASH_SAMPLES.items():
        ob = mv.clash_proxy_to_outbound(p)
        if not ob:
            FAIL.append(f"[STRUCT] {name}: clash 转译失败")
            print(f"  ❌ {name}: clash 转译失败")
            continue
        link = mv.outbound_to_v2ray_link(dict(ob), "Test-" + name)
        rp = mv.parse_node_uri(link) if link else None
        exp_port = ob.get("server_port") or int(str(ob["server_ports"][0]).split(":")[0])
        if not rp or rp[3] != ob["type"] or rp[1] != ob["server"] or rp[2] != exp_port:
            FAIL.append(f"[STRUCT] {name}: 转译 roundtrip 失败")
            print(f"  ❌ {name}: 转译 roundtrip 失败")
            continue
        cp = mv.outbound_to_clash(dict(ob), "Test-" + name)
        if not cp or not cp.get("port"):
            FAIL.append(f"[STRUCT] {name}: clash 导出失败")
            print(f"  ❌ {name}: clash 导出失败")
            continue
        print(f"  ✅ {name}: {ob['type']} {ob['server']}:{exp_port}")
    # 越界端口: 不可为它建样本 (不该产出可解析 outbound), 故在此直测 parse_node_uri
    _mix = mv.parse_node_uri("hysteria2://pw@hop.example.com:443?sni=hop.example.com&mport=2087-2097,70000,443#x")
    _all = mv.parse_node_uri("hysteria2://pw@hop.example.com:443?sni=hop.example.com&mport=70000#x")
    _clash = mv.clash_proxy_to_outbound({"type": "hysteria2", "server": "hop.example.com",
                                         "port": 443, "password": "pw", "ports": "70000"})
    _mix_sp = _mix[0].get("server_ports") if _mix else None
    if _mix_sp != ["2087:2097", "443:443"]:
        FAIL.append(f"[PORT-BOUND] mport=2087-2097,70000,443 应逐个丢弃越界元素保留有效跳跃: {_mix_sp}")
        print(f"  ❌ 越界端口未逐个丢弃: {_mix_sp}")
    elif not _all or _all[0].get("server_ports") or _all[0].get("server_port") != 443:
        FAIL.append("[PORT-BOUND] mport=70000 全越界时应回落 server_port=443 而非产出越界 server_ports")
        print("  ❌ mport=70000 未回落 server_port")
    elif not _clash or _clash.get("server_ports"):
        FAIL.append(f"[PORT-BOUND] Clash ports=70000 同界: {_clash and _clash.get('server_ports')}")
        print("  ❌ Clash ports=70000 未被拦截")
    else:
        print("  ✅ 越界端口逐个丢弃 + 全越界回落 server_port (hy2 mport 与 clash ports 同界)")
    # PORT-BOUND 2: parse_node_uri 的单一守卫须同时卡住上界 (实测越界端口 uint16 out of
    # range 启动即 FATAL, 而个体解析器一律放行)。越界端口不该产出可解析 outbound →
    # 不建 SAMPLES, 在此直测; 五个 URI 覆盖四类 userinfo 形态 (uuid/百分号密码/明文密码/
    # ss 明文) 与 hy2:// 短前缀。
    _pb_uris = {
        "vless": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:{p}"
                 "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com"
                 "&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=0123abcd&type=tcp#x",
        "trojan": "trojan://pass%40word123@example.com:{p}?sni=www.example.com&allowInsecure=1&type=tcp#x",
        "hysteria2": "hysteria2://pass123@hy2.example.com:{p}?sni=hy2.example.com&insecure=1#x",
        "hy2": "hy2://pass123@hy2.example.com:{p}?sni=hy2.example.com&insecure=1#x",
        "ss": "ss://aes-256-gcm:cGFzc3dvcmQ%3D@ss.example.com:{p}#x",
    }
    _pb_bad = []
    for _pn, _pu in _pb_uris.items():
        # 70000 明显越界 / 65536 紧邻越界 (证明界是 <= MAX_PORT 而非 < ) / 0 沿用旧下界
        for _p in (70000, 65536, 0):
            if mv.parse_node_uri(_pu.format(p=_p)) is not None:
                _pb_bad.append(f"{_pn}:{_p} 未被拒")
        # 65535 是合法上界, 不得被收紧误杀
        if mv.parse_node_uri(_pu.format(p=65535)) is None:
            _pb_bad.append(f"{_pn}:65535 合法上界被误杀")
    # 端口跳跃节点的预检端口取自 server_ports[0] (2087), 必须照旧放行
    _pb_hop = mv.parse_node_uri(SAMPLES["hy2_hop"])
    if not _pb_hop or _pb_hop[2] != 2087:
        _pb_bad.append(f"hy2_hop 预检端口应取 server_ports[0]=2087 (实得 {_pb_hop and _pb_hop[2]})")
    if _pb_bad:
        for _b in _pb_bad:
            FAIL.append(f"[PORT-BOUND] {_b}")
        print(f"  ❌ parse_node_uri 端口界异常: {'; '.join(_pb_bad)}")
    else:
        print("  ✅ parse_node_uri 端口界 OK (70000/65536/0 拒 · 65535 收 · hy2_hop 取 server_ports[0]=2087)")
    # P2a: trojan-ws Host 头必须进 clash
    _tob = mv.clash_proxy_to_outbound(CLASH_SAMPLES["clash_trojan_ws"])
    _tcp = mv.outbound_to_clash(_tob, "t")
    if _tcp.get("ws-opts", {}).get("headers", {}).get("Host") != "tj.example.com":
        FAIL.append("[P2] trojan-ws clash Host 头丢失")
        print("  ❌ trojan-ws Host 头丢失")
    else:
        print("  ✅ trojan-ws Host 头保留")
    # P2b: vmess scy 保留 + 非法值回退 auto
    _vc = dict(json.loads(mv.b64_decode(SAMPLES["vmess_ws"][8:])))
    _vc["scy"] = "chacha20-poly1305"
    _vu = "vmess://" + mv.base64.b64encode(json.dumps(_vc).encode()).decode()
    _vp = mv.parse_vmess(_vu)
    _vc["scy"] = "nonsense"
    _vu2 = "vmess://" + mv.base64.b64encode(json.dumps(_vc).encode()).decode()
    _vp2 = mv.parse_vmess(_vu2)
    if not _vp or _vp.get("security") != "chacha20-poly1305" or not _vp2 or _vp2.get("security") != "auto":
        FAIL.append("[P2] vmess scy 保留/回退异常")
        print("  ❌ vmess scy 异常")
    else:
        print("  ✅ vmess scy 保留/回退 OK")
    # sing-box JSON 摄入 + 不支持类型跳过
    _sj = {"outbounds": [dict(outbounds["vless_reality_vision"], tag="x"),
                         {"type": "selector", "tag": "s", "outbounds": []},
                         {"type": "direct", "tag": "direct"}]}
    _suris = mv.singbox_json_to_uris(_sj)
    if len(_suris) != 1:
        FAIL.append(f"[P2] singbox JSON 摄入异常: {len(_suris)}")
        print("  ❌ singbox JSON 摄入异常")
    else:
        print("  ✅ singbox JSON 摄入 OK")
    _mini = "proxies:\n  - {type: ss, server: s.example.com, port: 8388, cipher: aes-256-gcm, password: pw}\n"
    _mgot = mv.extract_nodes_from_text(_mini)
    if len(_mgot) != 1 or not next(iter(_mgot)).startswith("ss://"):
        FAIL.append("[P2] Clash YAML 端到端提取异常")
        print("  ❌ Clash YAML 端到端提取异常")
    else:
        print("  ✅ Clash YAML 端到端提取 OK")
    if mv.clash_proxy_to_outbound({"type": "wireguard", "server": "x", "port": 1}) is not None:
        FAIL.append("[P2] wireguard 应被跳过")
        print("  ❌ wireguard 未跳过")
    else:
        print("  ✅ 不支持类型跳过 OK")
    if not isinstance(mv.get_rdns("127.0.0.1"), str):
        FAIL.append("[P2] get_rdns 返回类型异常")
        print("  ❌ get_rdns 异常")
    else:
        print("  ✅ get_rdns OK")
    # prefetch_rdns 契约 + classify_network_type 的 rdns 哨兵语义。
    # 分类循环改用并发预热后, 全靠这三个约定: 覆盖每个请求 IP / 重复输入去重 / 空输入回 {}。
    _pf_ips = ["81.19.66.1", "81.19.66.1", "8.8.8.8", "127.0.0.1"]
    _pf = mv.prefetch_rdns(_pf_ips)
    _pf_bad = []
    if not isinstance(_pf, dict):
        _pf_bad.append(f"未返回 dict (实得 {type(_pf).__name__})")
    else:
        for _ip in ("81.19.66.1", "8.8.8.8", "127.0.0.1"):
            if _ip not in _pf:
                _pf_bad.append(f"缺键 {_ip}")
            elif not isinstance(_pf[_ip], str):
                _pf_bad.append(f"{_ip} 的值非 str: {_pf[_ip]!r}")
        if len(_pf) != 3:
            _pf_bad.append(f"重复输入未去重: 3 个唯一 IP 实得 {len(_pf)} 键")
        if mv.prefetch_rdns([]) != {}:
            _pf_bad.append("空输入未返回 {}")
    if _pf_bad:
        for _b in _pf_bad:
            FAIL.append(f"[P5-PREFETCH] {_b}")
        print(f"  ❌ prefetch_rdns 契约: {'; '.join(_pf_bad)}")
    else:
        _with_ptr = [k for k, v in _pf.items() if v]
        print(f"  ✅ prefetch_rdns 契约 OK (3 唯一 IP 全覆盖 · 去重 · 空输入{{}} · 有 PTR: "
              f"{_with_ptr or '本机解析器未给 PTR (空串仍是合法结果)'})")
    # 哨兵: rdns="" 必须真的压掉内部反查, rdns=None (默认) 必须仍走反查。
    # 打桩把 get_rdns 换成"回放预热值", 于是默认路径与注入路径喂给第 5 步的 rDNS 字符串
    # 逐字节相同 —— 判定不等就说明注入没接上第 5 步。计数器单独钉住"查/不查"这件事。
    # 网络不容忍: 81.19.66.1 拿不到 PTR 时预热值就是 "", 断言退化成"已知无结果"路径, 仍合法。
    _pf_calls = []
    _pf_orig = mv.get_rdns

    def _pf_replay(ip):
        _pf_calls.append(ip)
        return _pf.get(ip, "")

    mv.get_rdns = _pf_replay
    try:
        _pf_injected = mv.classify_network_type("81.19.66.1", None, 6679, "Skynet", None,
                                                _pf.get("81.19.66.1", ""))
        if _pf_calls:
            _pf_bad.append(f'rdns="" 仍触发了内部反查: {_pf_calls}')
        _pf_default = mv.classify_network_type("81.19.66.1", None, 6679, "Skynet", None)
        if len(_pf_calls) != 1:
            _pf_bad.append(f"rdns=None (默认) 未触发内部反查 (实得 {len(_pf_calls)} 次)")
    finally:
        mv.get_rdns = _pf_orig
    assert mv.get_rdns is _pf_orig, "rDNS 桩未还原"
    if _pf_injected != _pf_default:
        _pf_bad.append(f"注入预热值与默认路径判定不一致: 注入 {_pf_injected} vs 默认 {_pf_default}")
    if _pf_bad:
        for _b in _pf_bad:
            FAIL.append(f"[P5-RDNS-SENTINEL] {_b}")
        print(f"  ❌ rdns 哨兵/判定等价: {'; '.join(_pf_bad)}")
    else:
        print(f"  ✅ rdns 哨兵 OK (rdns=\"\" 零反查 · rdns=None 反查 1 次) + 判定等价 "
              f"{_pf_injected} == {_pf_default}")
    _ssh = mv.parse_ssh("ssh://u:p@h.example.com:22#x")
    if not _ssh or mv.outbound_to_v2ray_link(_ssh, "t") != "":
        FAIL.append("[P2] ssh 应导出为空")
        print("  ❌ ssh 未导出为空")
    else:
        print("  ✅ ssh 导出为空 OK")
    if mv._ss_outbound("h", 8388, "aes-256-gcm", "pw") is None:
        FAIL.append("[P4] 合法 ss 方法被误杀")
        print("  ❌ 合法 ss 方法被误杀")
    elif mv._ss_outbound("h", 8388, "g~v^=my>k=", "pw") is not None:
        FAIL.append("[P4] 垃圾 ss 方法未拦截")
        print("  ❌ 垃圾 ss 方法未拦截")
    elif mv.parse_node_uri("ss://aes-256-gcm:Z2FyYmFnZXB3ZA@h.example.com:8388#x") is None:
        FAIL.append("[P4] ss 明文userinfo 解析回归")
        print("  ❌ ss 明文解析回归")
    elif mv._clean_fp("unsafe") != "" or mv._clean_fp("Chrome") != "chrome":
        FAIL.append("[P4] fingerprint 清洗异常")
        print("  ❌ fingerprint 清洗异常")
    else:
        _tj = mv.parse_trojan("trojan://pw@h.example.com:443?sni=h.example.com&fp=unsafe#x")
        _vr = mv.parse_vless("vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?encryption=none&security=reality&sni=h.example.com&fp=unsafe&pbk=QUJD&sid=#x")
        if not _tj or "utls" in (_tj.get("tls") or {}):
            FAIL.append("[P4] trojan 非法 fp 未剥离")
            print("  ❌ trojan 非法 fp 未剥离")
        elif not _vr or (_vr.get("tls") or {}).get("utls", {}).get("fingerprint") != "chrome":
            FAIL.append("[P4] reality 非法 fp 未回退 chrome")
            print("  ❌ reality 非法 fp 未回退")
        else:
            print("  ✅ ss 白名单 + fp 清洗 OK")
    # B1 回归: 去重指纹必须覆盖连接参数 (凭据相同 ≠ 同一节点)
    _fp_base = {"type": "vless", "tag": "node", "server": "dedup.example.com", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}
    _fp_ws = mv.cred_fingerprint(dict(_fp_base, transport={"type": "ws", "path": "/a"}))
    _fp_grpc = mv.cred_fingerprint(dict(_fp_base, transport={"type": "grpc", "service_name": "b"}))
    # 独立构造、插入顺序不同、tag 缺失但逐字节相同 → 真重复, 必须合并 (保留去重收益)
    _fp_dup1 = mv.cred_fingerprint({"type": "vless", "server": "dup.example.com", "server_port": 443,
                                    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tag": "node"})
    _fp_dup2 = mv.cred_fingerprint({"server_port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                                    "server": "dup.example.com", "type": "vless"})
    if _fp_ws == _fp_grpc:
        FAIL.append("[B1] 凭据相同但 transport 不同被判为重复: 未实测节点继承他人 alive/exit_ip/mitm_risk")
        print("  ❌ 去重指纹忽略 transport")
    elif _fp_dup1 != _fp_dup2:
        FAIL.append("[B1] 逐字节相同的重复节点指纹不一致, 去重失效")
        print("  ❌ 相同节点指纹不一致")
    else:
        print("  ✅ 去重指纹区分连接参数 + 合并真重复 OK")
    # M1 回归: 非 204 状态码 / 非空响应体 不是拦截证据
    #   旧启发式 `status in (301,302,403,407,502,503) or len(r.content) > 0` 会把源站
    #   403/404/500/302/407 的健康节点判为 TLS 劫持, 并被 mitm_risk 消费方整批剔除
    _tls_verify_failed = False  # 证书校验通过的 403 + 非空错误页场景
    if mv.is_tls_intercepted(tls_verify_failed=True) is not True:
        FAIL.append("[M1] TLS 证书校验失败未判为拦截")
        print("  ❌ 证书校验失败未判为拦截")
    elif mv.is_tls_intercepted(tls_verify_failed=_tls_verify_failed) is not False:
        FAIL.append("[M1] 非 204 状态码/非空响应体被误判为拦截 (旧启发式回归)")
        print("  ❌ 状态码/响应体启发式回归")
    else:
        print("  ✅ MITM 仅认证书校验失败 (403 + 非空响应体 不误杀) OK")
    if mv.tcp_precheck("127.0.0.1", 1, "vless") is not False:
        FAIL.append("[P3] 闭端口应判死")
        print("  ❌ 闭端口未判死")
    elif mv.tcp_precheck("127.0.0.1", 1, "hysteria2") is not True:
        FAIL.append("[P3] QUIC 系应放行")
        print("  ❌ QUIC 系未放行")
    elif mv.tcp_precheck("nonexistent.invalid", 443, "vless") is not False:
        FAIL.append("[P3] 不可解析域名应判死")
        print("  ❌ 不可解析域名未判死")
    else:
        print("  ✅ TCP 预检 OK")

    # ── resolve_host 的三条契约: 负缓存 / 同 host 单飞 / 两条平凡路径短路 ──
    # 三条断言全部打在"发了几条请求、缓存里有什么"上, 不打"解析结果对不对", 于是
    # 该 host 能否解析、走 DoH 还是走系统 DNS 兜底、链路是否可达, 结论都一样 (网络不容忍)。
    class _DohCounter:
        """透明包一层 DIRECT_SESSION: 只数 resolve_host 真正发出的 DoH 请求条数。
        走真实 Session (不伪造响应), 故统计的是真实请求, 与生产路径同一条。"""
        def __init__(self, inner):
            self._inner = inner
            self.n = 0
        def get(self, url, **kw):
            self.n += 1
            return self._inner.get(url, **kw)

    def _reset_dns_state():
        """三份状态一起清。测试之间互不污染, 且"平凡路径不留痕"那条断言才有意义。"""
        mv._DNS_CACHE.clear()
        mv._DNS_NEG_CACHE.clear()
        mv._DNS_LOCKS.clear()

    def _with_counted_doh(body):
        """把 mv.DIRECT_SESSION 换成计数包装, 跑完必定还原 (finally)。"""
        counter = _DohCounter(mv.DIRECT_SESSION)
        orig = mv.DIRECT_SESSION
        mv.DIRECT_SESSION = counter
        try:
            body(counter)
        finally:
            mv.DIRECT_SESSION = orig

    # (a) 负缓存: 第二次调用不得再发起任何解析。.invalid 是 RFC 2606 保留 TLD, 永不解析。
    _DEAD = "p2-neg-cache-probe.invalid"
    _reset_dns_state()
    _na = {}

    def _neg_body(c):
        _na["first"] = mv.resolve_host(_DEAD)
        _na["n1"] = c.n
        _na["second"] = mv.resolve_host(_DEAD)
        _na["n2"] = c.n

    _with_counted_doh(_neg_body)
    _nc_bad = []
    if _na.get("n1", 0) < 1:
        _nc_bad.append(f"首次调用没发出请求 (计数 {_na.get('n1')}) — 计数桩没生效, 本检查无意义")
    if _na.get("n2") != _na.get("n1"):
        _nc_bad.append(f"第二次仍发起了请求 {_na.get('n1')}→{_na.get('n2')} (负缓存未生效)")
    if _DEAD not in mv._DNS_NEG_CACHE:
        _nc_bad.append(f"负缓存里没有 {_DEAD}")
    if mv._DNS_CACHE.get(_DEAD):
        _nc_bad.append(f"不可解析的 host 不该进正缓存: {mv._DNS_CACHE.get(_DEAD)!r}")
    if _nc_bad:
        for _b in _nc_bad:
            FAIL.append(f"[P5-DNS-NEG] {_b}")
        print(f"  ❌ 负缓存: {'; '.join(_nc_bad)}")
    else:
        print(f"  ✅ 负缓存 OK (第2次零请求 {_na.get('n1')}→{_na.get('n2')} · 负缓存命中 · 未污染正缓存)")

    # (b) 单飞: 16 线程打同一个 host, 只能有 1 条 DoH 请求。断言的是**请求条数**,
    #     与该 host 是否解析得出无关 (解析成功走正缓存、解析失败走负缓存, 都是 1 条)。
    _reset_dns_state()
    _sb = {}

    def _sf_body(c):
        with ThreadPoolExecutor(max_workers=16) as ex:
            futs = [ex.submit(mv.resolve_host, "example.com") for _ in range(16)]
            _sb["out"] = [f.result() for f in futs]
        _sb["n"] = c.n

    _with_counted_doh(_sf_body)
    _sf_bad = []
    if _sb.get("n") != 1:
        _sf_bad.append(f"16 线程同 host 发出 {_sb.get('n')} 条 DoH (期望 1) — 单飞失效")
    if len(set(_sb.get("out") or [])) != 1:
        _sf_bad.append(f"16 个线程返回值不一致: {sorted(set(_sb.get('out') or []))}")
    if _sf_bad:
        for _b in _sf_bad:
            FAIL.append(f"[P5-DNS-SF] {_b}")
        print(f"  ❌ 单飞: {'; '.join(_sf_bad)}")
    else:
        _uniq = sorted(set(_sb.get("out") or []))
        print(f"  ✅ 单飞 OK (16 线程 → {_sb.get('n')} 条 DoH · 16 值一致 {_uniq})")

    # (c) 两条平凡路径: 空 host 与 IP 字面量都必须零请求、零缓存、零锁。
    _reset_dns_state()
    _tv = {}

    def _tv_body(c):
        _tv["empty"] = mv.resolve_host("")
        _tv["ip"] = mv.resolve_host("1.2.3.4")
        _tv["n"] = c.n

    _with_counted_doh(_tv_body)
    _tr_bad = []
    if _tv.get("empty") != "":
        _tr_bad.append(f'空 host 应返回 "" (实得 {_tv.get("empty")!r})')
    if _tv.get("ip") != "1.2.3.4":
        _tr_bad.append(f'IP 字面量应原样返回 (实得 {_tv.get("ip")!r})')
    if _tv.get("n"):
        _tr_bad.append(f"平凡路径不得发请求 (发了 {_tv.get('n')} 条)")
    if mv._DNS_CACHE or mv._DNS_NEG_CACHE or mv._DNS_LOCKS:
        _tr_bad.append(f"平凡路径不得留痕: pos={dict(mv._DNS_CACHE)} neg={dict(mv._DNS_NEG_CACHE)} "
                       f"locks={dict(mv._DNS_LOCKS)}")
    if _tr_bad:
        for _b in _tr_bad:
            FAIL.append(f"[P5-DNS-TRIVIAL] {_b}")
        print(f"  ❌ 平凡路径: {'; '.join(_tr_bad)}")
    else:
        print("  ✅ 平凡路径 OK (\"\"→\"\" · 1.2.3.4→1.2.3.4 · 零请求零缓存零锁)")
    _reset_dns_state()
    assert not isinstance(mv.DIRECT_SESSION, _DohCounter), "DoH 计数包装未还原"

    # ── 阶段6: 导出端口不变式 (clash / v2ray 两条链共用 main_v2._export_port) ──
    # 缺陷背景 (读码确认, 非推测): 旧实现两条链各抄一遍端口取值且判据相反 —— clash 走真值
    # node.get("server_port"), v2ray 走存在性 "server_port" in node。于是 server_port=0 时
    # v2ray 照发 ":0", clash 却落到 server_ports 分支 → 同一节点两个客户端端口不同; 且
    # server_ports[0] 直接 int(...) 遇 "abc" 抛 ValueError, 一条畸形数据打断整批导出。
    # 三条不变式钉死: ① 导出端绝不吐越界端口 ② 两条链绝不分歧 ③ 畸形数据绝不抛异常。
    # 本阶段是纯 Python 断言: 不联网、不调 sing-box, 故与阶段2 的内核 check 是两类东西
    # (此处 check PASS 指不变式成立, 不是内核校验结论); 计数不重叠也不互相冒充。
    print()
    print("=" * 70)
    print("阶段6: 导出端口不变式 (纯 Python 断言, 不联网 · 不依赖内核)")
    print("=" * 70)
    _PV_KEEP = object()   # 哨兵: 与"字段存在但为空"区分开
    _PV = {"type": "hysteria2", "tag": "node", "server": "pv.example.com",
           "server_port": 443, "password": "pw",
           "tls": {"enabled": True, "server_name": "pv.example.com"}}

    def _pv_node(port=_PV_KEEP, hops=None):
        """在合法 hy2 节点上摆端口字段。port=_PV_KEEP 表示删掉 server_port (端口跳跃节点形态)。"""
        ob = dict(_PV)
        if port is _PV_KEEP:
            ob.pop("server_port", None)
        else:
            ob["server_port"] = port
        if hops is not None:
            ob["server_ports"] = hops
        return ob

    def _pv_probe(ob):
        """两条导出链一起跑。刻意不碰 mv._export_port —— 它本身就是本次修复的一部分, 拿它当
        前置条件会让全部用例因"函数不存在"一起变红, 而不是各自钉住各自的缺陷。
        异常不外泄: 折成 (clash, v2ray, 异常名) 三元组, 与成功路径同样三个元素, 否则未修复的
        代码会把解包本身炸掉, 报告成崩溃而不是失败。"""
        try:
            return mv.outbound_to_clash(dict(ob), "pv"), mv.outbound_to_v2ray_link(dict(ob), "pv"), None
        except Exception as e:
            return "EXC", "", type(e).__name__

    def _v2_port(link):
        """从导出链接的 authority 段直接读端口 (不过 parse_node_uri)。
        原因: parse_hysteria2 一见 mport 就 pop 掉 server_port (main_v2:988), 于是
        server_port 与 server_ports 同时在场的节点 roundtrip 回来必是首跳端口 —— 那量到
        的是解析器既定优先级, 不是导出端口。导出端的端口只能读链接原文。
        缺端口 / 空端口 / 非数字一律返回 None: 端口畸形正是被测对象, 取端口的辅助函数
        自己先抛 (未修复代码会导出 "host:?sni=..." 这种空端口) 就没法报告缺陷了。"""
        if not link:
            return None
        authority = link.split("://", 1)[-1].split("#", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
        tok = authority.rsplit(":", 1)[-1] if ":" in authority else ""
        return int(tok) if tok.isdecimal() else None

    # 每个用例一个断言: _export_port / clash port / v2ray 链接再解析回来的端口, 三处必须同时
    # 等于期望值 (期望 None = 该节点应被拒: clash→None, v2ray→空串)。
    _PV_CASES = [
        ("port_1_合法下界",              _pv_node(port=1),                   1),
        ("port_443_常规",                _pv_node(port=443),                 443),
        ("port_65535_合法上界",          _pv_node(port=65535),               65535),
        ("port_0_下界越界",              _pv_node(port=0),                   None),
        ("port_65536_上界越一",          _pv_node(port=65536),               None),
        ("port_70000_实测FATAL值",       _pv_node(port=70000),               None),
        ("server_port_空串",             _pv_node(port=""),                  None),
        ("server_port_为None",           _pv_node(port=None),                None),
        ("hops_非数字元素",              _pv_node(hops=["abc:def"]),         None),
        ("hops_空串元素",                _pv_node(hops=[""]),                None),
        ("hops_两端越界",                _pv_node(hops=["70000:70001"]),     None),
        ("hops_首元素越界不跳后一元素",   _pv_node(hops=["70000:70001", "2087:2097"]), None),
        ("hops_非下标类型(字典)",        _pv_node(hops={"a": 1}),            None),
        ("hops_首元素为None",            _pv_node(hops=[None]),              None),
        # ↓ 回落与两链一致性: 旧实现在 server_port=0 上 v2ray 发 ":0" 而 clash 走跳跃分支
        ("回落_单端口0且跳跃合法",       _pv_node(port=0, hops=["2087:2097", "443:443"]), 2087),
        ("回落_单端口65536且跳跃合法",   _pv_node(port=65536, hops=["2087:2097"]), 2087),
        ("不回落_单端口合法优先于跳跃",   _pv_node(port=443, hops=["2087:2097"]), 443),
        ("两链一致_server_port0无跳跃",  _pv_node(port=0),                   None),
    ]
    _PV_BAD = []
    for _pn, _pnode, _want in _PV_CASES:
        _err = []
        _cp, _v2, _exc = _pv_probe(_pnode)
        if _exc:
            # 畸形 server_ports 元素不得打断导出: 导出端一崩就是整批订阅丢光
            _err.append(f"导出链抛出 {_exc} (畸形数据不得中断整批导出)")
        else:
            _v2p = _v2_port(_v2)
            if _want is None:
                # 越界端口宁可不导出: clash 返回 None, v2ray 返回空串 (两条链原有契约不变)
                if _cp is not None:
                    _err.append(f"clash 应为 None 实得 port={_cp.get('port')!r}")
                if _v2 != "":
                    _err.append(f"v2ray 应为空串 实得 {_v2[:60]!r}")
            else:
                if not _cp or _cp.get("port") != _want:
                    _err.append(f"clash port 期望 {_want} 实得 {_cp and _cp.get('port')!r}")
                if _v2p != _want:
                    _err.append(f"v2ray 链接端口期望 {_want} 实得 {_v2p!r}")
                # 无跳跃列表的节点再加一条 roundtrip: 导出的链接要能被自家解析器读回同一端口
                if not _pnode.get("server_ports"):
                    _rep = mv.parse_node_uri(_v2) if _v2 else None
                    if not _rep or _rep[2] != _want:
                        _err.append(f"v2ray roundtrip 期望 {_want} 实得 {_rep and _rep[2]!r}")
        if _err:
            _PV_BAD.extend(f"{_pn}: {_e}" for _e in _err)
            print(f"  ❌ {_pn}: {'; '.join(_err)}")
        else:
            # f-string 表达式里不能带反斜杠 (3.11), 故先把展示文案取出来
            _shown = "拒 (clash=None / v2ray 空串)" if _want is None else _want
            print(f"  ✅ {_pn}: check PASS (端口 {_shown} · clash/v2ray 两链一致)")
    # _export_port 是本次修复引入的单一取值入口: 上面的用例已各自钉住两条链的行为, 这里再钉
    # 死"两条链确实共用它" —— 界若哪天在外泄一份新判据, 这条会先炸。
    if not hasattr(mv, "_export_port"):
        _PV_BAD.append("main_v2._export_port 不存在: 两条导出链没有共用的取值入口")
    else:
        for _pn, _pnode, _want in _PV_CASES:
            try:
                _hp = mv._export_port(dict(_pnode))
            except Exception as e:
                _PV_BAD.append(f"{_pn}: _export_port 抛出 {type(e).__name__}")
                continue
            if _hp != _want:
                _PV_BAD.append(f"{_pn}: _export_port 期望 {_want} 实得 {_hp!r}")
    if _PV_BAD:
        for _b in _PV_BAD:
            FAIL.append(f"[P6-PORT] {_b}")
        print(f"  ❌ 导出端口不变式: {len(_PV_BAD)} 项不符")
    else:
        print(f"  ✅ 导出端口不变式 OK ({len(_PV_CASES)} 用例 · 0/65536/70000 拒 · 65535/1 收 · "
              f"畸形 server_ports 不抛 · server_port 越界回落首跳 · 两链零分歧)")

    # clash proxy["ports"] 跳跃列表: 旧实现把 server_ports 原样 join, 坏元素直接变成
    # "443-443" 这类垃圾串。改为逐个校验两端, 全灭则整个不设 ports 键 (不写空串)。
    _PF_CASES = [
        ("ports_合法区间原样保留",     _pv_node(hops=["2087:2097", "443:443"]), True,  "2087-2097,443-443"),
        ("ports_逐个丢弃越界与畸形",   _pv_node(hops=["2087:2097", "70000:70001", "abc:def", "", "0:10", "443:443"]),
         True,  "2087-2097,443-443"),
        # server_port 与 server_ports 同时在场 (结构化源 clash→outbound 两条路径都可能给到):
        # 端口能取到但跳跃列表全灭 → 保留节点, 只是不下发 ports
        ("ports_全灭则不设ports键",   _pv_node(port=443, hops=["70000:70001", "abc:def"]), True, None),
        ("ports_全灭且无单端口则丢弃", _pv_node(hops=["70000:70001", "abc:def"]), False, None),
    ]
    _PF_BAD = []
    for _fn, _fnode, _want_proxy, _want_ports in _PF_CASES:
        _err = []
        try:
            _fp = mv.outbound_to_clash(dict(_fnode), "pf")
        except Exception as e:
            _fp = "EXC"
            _err.append(f"抛出 {type(e).__name__}: {e}")
        if not _err:
            if _want_proxy and _fp:
                if _want_ports is None:
                    if "ports" in _fp:
                        _err.append(f"ports 应整个不设 实得 {_fp['ports']!r}")
                elif _fp.get("ports") != _want_ports:
                    _err.append(f"ports 期望 {_want_ports!r} 实得 {_fp.get('ports')!r}")
            elif _want_proxy and not _fp:
                _err.append("合法节点被误丢")
            elif not _want_proxy and _fp is not None:
                _err.append(f"应丢弃该节点 实得 port={_fp.get('port')!r}")
        if _err:
            _PF_BAD.extend(f"{_fn}: {_e}" for _e in _err)
            print(f"  ❌ {_fn}: {'; '.join(_err)}")
        else:
            print(f"  ✅ {_fn}: check PASS (ports={_want_ports!r} · "
                  f"proxy={'保留' if _want_proxy else '丢弃'})")
    if _PF_BAD:
        for _b in _PF_BAD:
            FAIL.append(f"[P6-PORTS] {_b}")
        print(f"  ❌ clash ports 校验: {len(_PF_BAD)} 项不符")
    else:
        print(f"  ✅ clash ports 校验 OK ({len(_PF_CASES)} 用例 · 坏元素逐个丢弃 · 全灭不设键)")

    # 跨链一致性: clash 的 ports 与 v2ray 的 mport 必须完全相同。修复前 v2ray 直接
    # ",".join(p.replace(":", "-")) 不过滤, 同一节点 clash 得 "2087-2097" 而 v2rayN 得
    # "2087-2097,70000-70001,abc-def" —— 两个客户端对同一节点拿到不同的跳跃列表。
    _XC_BAD = []
    for _xn, _xnode in (
        ("hops_全畸形+越界", _pv_node(port=443, hops=["2087:2097", "70000:70001", "abc:def", "", "0:10"])),
        ("hops_合法区间",     _pv_node(port=443, hops=["2087:2097", "443:443"])),
        ("hops_全灭",         _pv_node(port=443, hops=["70000:70001", "abc:def"])),
        ("hops_无跳跃列表",   _pv_node(port=443)),
    ):
        _xc = mv.outbound_to_clash(dict(_xnode), "xc")
        _xv = mv.outbound_to_v2ray_link(dict(_xnode), "xc")
        _xcp = _xc.get("ports") if _xc else None
        _xmp = None
        if _xv and "mport=" in _xv:
            _xmp = urllib.parse.parse_qs(urllib.parse.urlparse(_xv).query).get("mport", [None])[0]
        if _xcp != _xmp:
            _XC_BAD.append(f"{_xn}: clash ports={_xcp!r} v2ray mport={_xmp!r}")
    if _XC_BAD:
        for _b in _XC_BAD:
            FAIL.append(f"[P6-XCHAIN] {_b}")
        print(f"  ❌ clash/v2ray 跳跃列表一致性: {len(_XC_BAD)} 项不符")
    else:
        print("  ✅ clash/v2ray 跳跃列表一致 OK (4 用例 · ports 与 mport 完全相同)")

    # ── 阶段7: anytls / ssh 凭据锚点 + 端口可选性 (纯 Python 断言, 不联网 · 不依赖内核) ──
    # 缺陷背景 (读码 + 跑旧实现实测, 非推测): 两个解析器的凭据类都是 [^@#/?]+, 同时排除
    # 了 @ 与 /, 于是密码含这两者时整条节点被丢 —— 实测旧实现 parse_node_uri 返回 None:
    #   anytls://pa@ss@h.com:443 / anytls://pa/ss@h.com:443 / ssh://user:p@ss@h.com:22
    #   / ssh://user:p/ss@h.com:22
    # 与 parse_tuic 同一类缺陷、同一修法 (以最后一个 @ 为锚点分割)。ssh 另有两处实测缺陷:
    #   ":(\d+)?" 的冒号是必需的, 故 int(port or 22) 的 22 兜底是死代码
    #   (ssh://user:pass@h.com 实测 None); 且无尾锚 → ssh://user:pass@h.com:22junk 被
    #   静默截断成端口 22。
    # 本阶段只钉解析器: 期望值是逐条从上面的实测证据写死的, 不调 sing-box (密码含 @ / /
    # : 的 ssh/anytls outbound 本阶段交给阶段2 那类内核 check, 这里是纯 Python 断言,
    # 与阶段6 同性质 —— "check PASS" 指不变式成立, 不是内核校验结论)。
    print()
    print("=" * 70)
    print("阶段7: anytls / ssh 凭据锚点与端口不变式 (纯 Python 断言, 不联网 · 不依赖内核)")
    print("=" * 70)

    def _p7_probe(uri):
        """解析一条 URI 并折成可比较的 (ok, 摘要)。异常不外泄: 折成 (False, 异常名) 三元组,
        与成功路径同样三个元素, 否则未修复的代码会把解包本身炸掉, 报告成崩溃而不是失败。"""
        try:
            r = mv.parse_node_uri(uri)
            if not r:
                return False, "None (整条节点被丢)", None
            ob, server, port, proto = r
            return True, ob, (server, port, proto)
        except Exception as e:
            return False, f"EXC {type(e).__name__}", None

    # ── anytls ──
    # (用例名, uri, 期望 password, 期望 server, 期望端口, 期望 tls 子集或 None)
    _P7_ANY = [
        # ↓ 旧实现整条丢弃的四类密码 (实测 pre=None)
        ("anytls_密码含@",        "anytls://pa@ss@at.example.com:443",        "pa@ss",  "at.example.com", 443,  None),
        ("anytls_密码含/",        "anytls://pa/ss@at.example.com:443",        "pa/ss",  "at.example.com", 443,  None),
        ("anytls_密码含:旧实现已可", "anytls://pa:ss@at.example.com:443",      "pa:ss",  "at.example.com", 443,  None),
        ("anytls_密码含@与/",     "anytls://pa/ss@word@at.example.com:443",  "pa/ss@word", "at.example.com", 443, None),
        # ↓ percent-encoded 仍要照旧解码 (旧实现一直能过, 不得回归)
        ("anytls_密码percent编码", "anytls://pa%40ss%2Fword@at.example.com:443", "pa@ss/word", "at.example.com", 443, None),
        # ↓ 常规形态与 IPv6
        ("anytls_常规",           "anytls://pass123@at.example.com:443",      "pass123", "at.example.com", 443, None),
        ("anytls_IPv6主机",       "anytls://pass123@[2001:db8::1]:443",       "pass123", "[2001:db8::1]",  443, None),
        ("anytls_IPv6回环",       "anytls://pass@[::1]:443",                  "pass",    "[::1]",         443, None),
        # ↓ 查询参数: sni / insecure / alpn 三者必须与旧实现一致 (含 allowInsecure 别名)
        ("anytls_查询_sni",       "anytls://pass@q.example.com:443?sni=s.example.com",
                                                            "pass", "q.example.com", 443,
         {"server_name": "s.example.com", "insecure": False}),
        ("anytls_查询_insecure",  "anytls://pass@q.example.com:443?sni=s.example.com&insecure=1",
                                                            "pass", "q.example.com", 443,
         {"server_name": "s.example.com", "insecure": True}),
        ("anytls_查询_alpn",      "anytls://pass@q.example.com:443?alpn=h2,http/1.1",
                                                            "pass", "q.example.com", 443,
         {"alpn": ["h2", "http/1.1"]}),
        ("anytls_查询_三者同在",   "anytls://pa@ss/q@q.example.com:443?sni=s.example.com&insecure=1&alpn=h3",
                                                            "pa@ss/q", "q.example.com", 443,
         {"server_name": "s.example.com", "insecure": True, "alpn": ["h3"]}),
        ("anytls_查询_allowInsecure别名", "anytls://pass@q.example.com:443?allowInsecure=1",
                                                            "pass", "q.example.com", 443,
         {"server_name": "q.example.com", "insecure": True}),
        # ↓ 尾片段仍按 #name 处理 (不得混进密码)
        ("anytls_尾片段不进密码", "anytls://pa@ss@at.example.com:443#TestAnytlsAt",
                                                            "pa@ss", "at.example.com", 443, None),
    ]
    # ── ssh ──
    # (用例名, uri, 期望 password 或 None, 期望 user, 期望 server, 期望端口)
    _P7_SSH = [
        ("ssh_密码含@",          "ssh://user:p@ss@ssh.example.com:22",  "p@ss", "user", "ssh.example.com", 22),
        ("ssh_密码含/",          "ssh://user:p/ss@ssh.example.com:22",  "p/ss", "user", "ssh.example.com", 22),
        ("ssh_密码含:",          "ssh://user:p:ss@ssh.example.com:22",  "p:ss", "user", "ssh.example.com", 22),
        ("ssh_密码含@与/与:",     "ssh://user:a:b/c@d@ssh.example.com:22", "a:b/c@d", "user", "ssh.example.com", 22),
        ("ssh_密码percent编码",   "ssh://user:p%40ss%2Fword@ssh.example.com:22", "p@ss/word", "user", "ssh.example.com", 22),
        ("ssh_无密码",           "ssh://user@ssh.example.com:22",       None, "user", "ssh.example.com", 22),
        ("ssh_常规带端口",        "ssh://user:pass@ssh.example.com:22",  "pass", "user", "ssh.example.com", 22),
        ("ssh_IPv6主机带端口",    "ssh://user:pass@[2001:db8::1]:22",    "pass", "user", "[2001:db8::1]",  22),
        # ↓ 端口可选 (旧实现 int(port or 22) 是死代码, 实测无端口 → None)
        ("ssh_无端口落22",        "ssh://user:pass@ssh.example.com",      "pass", "user", "ssh.example.com", 22),
        ("ssh_无端口无密码落22",  "ssh://user@ssh.example.com",          None, "user", "ssh.example.com", 22),
        ("ssh_IPv6无端口落22",    "ssh://user:pass@[2001:db8::1]",       "pass", "user", "[2001:db8::1]",  22),
        ("ssh_空端口视同无端口",  "ssh://user:pass@ssh.example.com:",     "pass", "user", "ssh.example.com", 22),
        ("ssh_端口1",            "ssh://user:pass@ssh.example.com:1",   "pass", "user", "ssh.example.com", 1),
        ("ssh_端口65535",         "ssh://user:pass@ssh.example.com:65535", "pass", "user", "ssh.example.com", 65535),
        # ↓ 尾随查询串放行但忽略: 旧实现无尾锚时是接受的 (查询参数被静默丢弃 —— ssh 出站
        #   本就没有 TLS/SNI 可透传), $ 锚定若把查询串一并拒掉就是"节点由可用变丢弃"的
        #   净损失。这条与下面的脏尾巴必须拒形成对照, 别后来者顺手把查询串也拒了。
        ("ssh_端口后带查询串",    "ssh://user:pass@ssh.example.com:22?x=1",  "pass", "user", "ssh.example.com", 22),
        ("ssh_查询串带sni",       "ssh://user:pass@ssh.example.com:22?sni=x.com", "pass", "user", "ssh.example.com", 22),
        ("ssh_无端口带查询串",    "ssh://user:pass@ssh.example.com?x=1",   "pass", "user", "ssh.example.com", 22),
        ("ssh_查询串带name",      "ssh://user:pass@ssh.example.com:22?x=1#N", "pass", "user", "ssh.example.com", 22),
        # ↓ $ 收口: 端口后的脏尾巴必须被拒 (旧实现实测静默截断成 22 / 甚至 2)
        ("ssh_端口后脏字母",      "ssh://user:pass@ssh.example.com:22junk", None, None, None, None),
        ("ssh_端口后非数字",      "ssh://user:pass@ssh.example.com:junk",   None, None, None, None),
        ("ssh_端口后夹空格",      "ssh://user:pass@ssh.example.com:2 2",    None, None, None, None),
        ("ssh_端口后带路径",      "ssh://user:pass@ssh.example.com:22/extra", None, None, None, None),
        ("ssh_端口0越界",         "ssh://user:pass@ssh.example.com:0",      None, None, None, None),
    ]
    _P7_PASS = 0

    def _p7_run(label, uri, checks, want_txt):
        """跑一条"应解析成功"的用例, 逐键比对 outbound, 并交叉核对 parse_node_uri
        返回的四元组与 outbound 自洽 (两处读法漂移过, 故两条都钉)。"""
        nonlocal _P7_PASS
        ok, ob, meta = _p7_probe(uri)
        if not ok:
            FAIL.append(f"[P7] {label}: 应解析成功 实得 {ob}")
            print(f"  ❌ {label}: check FAIL → 应解析成功 实得 {ob}")
            return
        err = [f"{key} 期望 {want!r} 实得 {ob.get(key)!r}" for key, want in checks if ob.get(key) != want]
        if meta != (ob["server"], ob["server_port"], ob["type"]):
            err.append(f"parse_node_uri 四元组与 outbound 不自洽: {meta!r}")
        if err:
            FAIL.extend(f"[P7] {label}: {_e}" for _e in err)
            print(f"  ❌ {label}: check FAIL → {'; '.join(err)}")
        else:
            _P7_PASS += 1
            print(f"  ✅ {label}: check PASS ({want_txt})")

    def _p7_run_reject(label, uri):
        """跑一条"应被拒"的用例: 解析器返回 None (parse_node_uri) 或节点本身不得存在。"""
        nonlocal _P7_PASS
        ok, ob, _meta = _p7_probe(uri)
        if ok:
            FAIL.append(f"[P7] {label}: 应被拒 实得 {ob!r}")
            print(f"  ❌ {label}: check FAIL → 应被拒 实得 {ob!r}")
        else:
            _P7_PASS += 1
            print(f"  ✅ {label}: check PASS (拒: {ob})")

    for _n, _u, _pw, _sv, _pt, _tls in _P7_ANY:
        # tls 三键恒在 (enabled / server_name 默认取 host / insecure 默认 false), alpn 仅在
        # 给了 alpn 参数时出现: 故把默认值物化后整块比对, 而不是比对子集 (子集比对会把
        # "多出一个键"这类漂移漏过去)。_tls 只写与默认不同的键。
        _tls_want = {"enabled": True, "server_name": _sv, "insecure": False, **(_tls or {})}
        _p7_run(_n, _u,
                [("type", "anytls"), ("tag", "node"), ("password", _pw),
                 ("server", _sv), ("server_port", _pt), ("tls", _tls_want)],
                f"pw={_pw!r} {_sv}:{_pt}")

    for _n, _u, _pw, _usr, _sv, _pt in _P7_SSH:
        if _sv is None:
            # 该行是"应被拒"用例 (_sv 是唯一的判别位: 期望 server 只有真接受才有值)
            _p7_run_reject(_n, _u)
        elif _pw is None:
            # 无密码形态: 不得凭空长出 password 键 (返回 dict 形状不得变)
            _ok, _ob, _ = _p7_probe(_u)
            if _ok and "password" in _ob:
                FAIL.append(f"[P7] {_n}: 无密码形态不应有 password 键 实得 {_ob['password']!r}")
                print(f"  ❌ {_n}: check FAIL → 无密码形态不应有 password 键")
                continue
            _p7_run(_n, _u,
                    [("type", "ssh"), ("tag", "node"), ("user", _usr),
                     ("server", _sv), ("server_port", _pt)],
                    f"{_usr}@{_sv}:{_pt} (无 password 键)")
        else:
            _p7_run(_n, _u,
                    [("type", "ssh"), ("tag", "node"), ("user", _usr), ("password", _pw),
                     ("server", _sv), ("server_port", _pt)],
                    f"{_usr}:{_pw!r}@{_sv}:{_pt}")

    # anytls roundtrip: outbound_to_v2ray_link 已有 anytls 分支 (main_v2:2748), 用
    # urllib quote() 导出 —— quote 默认 safe="/", 斜杠不转义, 于是密码里的裸 / 会原样进
    # 链接, 旧解析器读不回自己导出的链接 (与阶段1 tuic_pw_slash 同一机理)。故这条
    # roundtrip 是"修好凭据锚点"的端到端证据: 导出 → 再解析 → 密码逐字节相同。
    # ssh 没有导出分支 (outbound_to_v2ray_link / outbound_to_clash 都不认 ssh, 实测
    # 分别返回 "" / None), 故不给它造导出器, 只在解析器层断言。
    for _rtn, _rtpw in (("roundtrip_anytls_密码含@", "pa@ss"),
                        ("roundtrip_anytls_密码含/", "pa/ss"),
                        ("roundtrip_anytls_密码含@与/", "pa/ss@word"),
                        ("roundtrip_anytls_密码含:", "pa:ss")):
        _rt_err = []
        try:
            _node = {"type": "anytls", "tag": "node", "server": "rt.example.com",
                     "server_port": 443, "password": _rtpw,
                     "tls": {"enabled": True, "server_name": "rt.example.com", "insecure": True}}
            _link = mv.outbound_to_v2ray_link(dict(_node), "rt")
            _rep = mv.parse_node_uri(_link) if _link else None
            if not _rep:
                _rt_err.append(f"导出链接 {_link!r} 再解析为 None")
            else:
                if _rep[0].get("password") != _rtpw:
                    _rt_err.append(f"密码漂移 {_rtpw!r} → {_rep[0].get('password')!r}")
                if (_rep[1], _rep[2], _rep[3]) != ("rt.example.com", 443, "anytls"):
                    _rt_err.append(f"server/port/proto 漂移 → {_rep[1:4]!r}")
        except Exception as e:
            _rt_err.append(f"抛出 {type(e).__name__}")
        if _rt_err:
            FAIL.extend(f"[P7-RT] {_rtn}: {_e}" for _e in _rt_err)
            print(f"  ❌ {_rtn}: check FAIL → {'; '.join(_rt_err)}")
        else:
            _P7_PASS += 1
            print(f"  ✅ {_rtn}: check PASS (密码 {_rtpw!r} 导出→再解析逐字节相同)")
    _P7_TOTAL = len(_P7_ANY) + len(_P7_SSH) + 4   # +4 = roundtrip 用例
    if _P7_PASS == _P7_TOTAL:
        print(f"  ✅ 阶段7 汇总 OK ({_P7_PASS}/{_P7_TOTAL} 用例全绿 · anytls {len(_P7_ANY)} · "
              f"ssh {len(_P7_SSH)} · roundtrip 4 · 零 sing-box 调用 · 零网络 I/O)")
    else:
        print(f"  ❌ 阶段7 汇总: {_P7_PASS}/{_P7_TOTAL} 用例不符 (明细见上方 ❌ 行与末尾失败清单)")

    print()
    print("=" * 70)
    if FAIL:
        print(f"共 {len(FAIL)} 项失败:")
        for f in FAIL:
            print(f"  - {f}")
        if SKIPPED:
            print(f"另有 {len(SKIPPED)} 项被豁免未校验:")
            for s in SKIPPED:
                print(f"  - {s}")
        sys.exit(1)
    elif SKIPPED:
        print(f"已跑项目全部通过, 但有 {len(SKIPPED)} 项**未校验** (退出码 0 不代表全量验证通过):")
        for s in SKIPPED:
            print(f"  - {s}")
    else:
        print("全部测试通过 ✅")


if __name__ == "__main__":
    run_test()
