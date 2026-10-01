#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单元自测: 全协议解析器 + sing-box check 配置合法性 + 分类逻辑"""
import os, sys, json

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
    # TUIC v5
    "tuic": "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass123@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com&allow_insecure=1#TestTuic",
    # AnyTLS
    "anytls": "anytls://pass123@anytls.example.com:443?sni=anytls.example.com&insecure=1#TestAnytls",
    # IPv6 字面量 (旧版正则必死的场景)
    "vless_ipv6": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443?encryption=none&security=tls&sni=v6.example.com&type=tcp#TestIPv6",
    # 域名含端口非常规 (解析应成功)
    "vless_path_edge": "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:8443?encryption=none&security=none&type=ws&path=%2Fed#TestEdge",
}

FAIL = []

def run_test():
    print("=" * 70)
    print("阶段1: 协议解析器单元测试 (17 个样本)")
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
        if name == "hy2_hop":
            assert ob.get("server_ports"), "mport 端口跳跃丢失"
            # 实测约束: 不能有裸单端口
            for p in ob["server_ports"]:
                assert ":" in p, f"裸单端口 {p} 会导致 sing-box FATAL"
        if name == "tuic":
            assert ob.get("uuid") and ob.get("password") and ob.get("congestion_control")
        if name == "anytls":
            assert ob.get("password") and ob["tls"]["enabled"]

    print()
    print("=" * 70)
    print(f"阶段2: sing-box check 配置合法性 ({len(outbounds)} 个 outbound)")
    print("=" * 70)
    if not SB:
        print(f"  ⚠️ SKIP: 未找到 sing-box 二进制 (已探测: {', '.join(_SB_CANDIDATES)})")
        print("  ⚠️ 跳过配置合法性检查 (不判失败), 继续阶段3")
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
    print("阶段3: 网络类型分类逻辑 (离线)")
    print("=" * 70)
    cases = [
        # (ip, asn, org, 期望 net_type)
        ("104.16.1.1", 13335, "cloudflare", "cdn"),             # CF 段硬判
        ("172.67.10.1", 13335, "Cloudflare, Inc.", "cdn"),
        ("8.8.8.8", 15169, "Google LLC", "cdn"),                 # Google 公共 DNS 段
        ("23.94.10.1", 36352, "ColoCrossing", "datacenter"),    # IDC ASN
        ("211.72.35.1", 3462, "Chunghwa Telecom", "residential"),# 台湾中华电信家宽
        ("61.220.50.1", 3462, "CHT", "residential"),
        ("219.85.10.1", 17676, "Softbank BB", "residential"),   # 日本软银家宽
        ("81.19.66.1", 6679, "Skynet", "unknown"),               # 无明显特征
    ]
    for ip, asn, org, expect in cases:
        got, conf = mv.classify_network_type(ip, None, asn, org, None)
        mark = "✅" if got == expect else ("⚠️" if expect == "unknown" else "❌")
        if got != expect and expect != "unknown":
            FAIL.append(f"[CLASSIFY] {ip} {org}: 期望 {expect} 实得 {got}")
        print(f"  {mark} {ip} ({org}) → {got} conf={conf}")

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
            if name == "hy2_hop":
                assert cp.get("ports"), "mport ports 丢失"
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
    _ssh = mv.parse_ssh("ssh://u:p@h.example.com:22#x")
    if not _ssh or mv.outbound_to_v2ray_link(_ssh, "t") != "":
        FAIL.append("[P2] ssh 应导出为空")
        print("  ❌ ssh 未导出为空")
    else:
        print("  ✅ ssh 导出为空 OK")

    print()
    print("=" * 70)
    if FAIL:
        print(f"共 {len(FAIL)} 项失败:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("全部测试通过 ✅")


if __name__ == "__main__":
    run_test()
