# WebSocketUpgradeOriginGate 0.1.1

作者：dhtfish98。此项目独立实现**仅供本机研究**的 WebSocket HTTP/1.1 Upgrade 授权门：必须同时满足精确目标 `Host`、被允许的页面 `Origin` 和有效合成会话 Cookie。`Origin` 是浏览器跨来源约束，不是身份认证；非浏览器客户端可以自行填入 Origin，因此有效会话仍是独立必要条件。

[源码](../src)与[测试](../tests)保持原有路径，仅含代码与包元数据；本项目许可证保存在「项目文档」，构建环境、wheel/sdist、浏览器日志与实验收据均写入未跟踪的 `Build` 目录。

## 行为与边界

服务仅绑定 `127.0.0.1` 的随机端口，接受 `/socket` 的 WebSocket 版本 13 握手。握手格式不合法返回 400；目标 Host、页面 Origin 或会话不符合策略时返回 403，且不会返回 101、读取应用消息或增加消息计数。允许的连接返回 101，能处理一个客户端掩码文本帧 `ping` 并回送 `ack`。会话由本机内存生成，保存的是令牌散列；决策事件只记录 Cookie 是否存在、无秘密的合成会话标签、与固定允许来源及目标 Host 的匹配结果，非法原始 Origin/Host 值不进入事件。调用方不可将秘密当作会话标签。

包的最小调用：

```python
from websocket_upgrade_origin_gate import GateServer, SessionRegistry, UpgradeGate

sessions = SessionRegistry()
synthetic_token = sessions.issue("local_session")
gate = UpgradeGate(allowed_origin="http://127.0.0.1:8001", sessions=sessions)
with GateServer(gate) as server:
    print(server.expected_host)
    # 仅供自有本机实验：由页面服务器和浏览器发起 Upgrade。
```

## 自有实验

测试启动两个仅监听 `127.0.0.1`、端口不同的页面来源 A/B，以及本机 WebSocket 服务。故意弱化的**测试专用基线**只验 Cookie，B 页面携带有效合成会话也能完成 Upgrade；该基线位于 `tests/`，不会进入 wheel。正式服务要求 A 来源、正确目标 Host 和有效会话，B 即使携带同一 Cookie 也在握手前收到 403。原始套接字客户端验证握手头、`Sec-WebSocket-Accept` 和掩码帧；真实 Chrome 页面与 iframe 验证浏览器自动发送的 A/B Origin 和 Cookie。测试还包括空/缺失 Origin、伪造或撤销的会话、缺失或重复 Cookie、错误 Host、重复 Origin 和无效 WebSocket Key。

复现入口：

```text
python3 .github/scripts/validate.py
```

入口保存每一步的真实退出码、源码清单和散列、安装版测试、`Build/lab-installed.json` 原始握手矩阵及 `Build/browser-installed.json` 浏览器实测。以本地 `Build/validation.json` 的当前状态为准。浏览器运行使用 Build 下的一次性配置，结束后删除；需要 macOS 上的 Google Chrome。公开版还须按该提交核对 CI、标签与 Release 附件。

## 来源与许可

问题范围参考 [python-websockets/websockets 固定快照中的 Origin 握手处理](https://github.com/python-websockets/websockets/blob/d6b0a6203a24057c57a425834ea41acee0a7ea70/src/websockets/server.py#L2044-L2098)，该上游源码的许可证是 [BSD-3-Clause](https://github.com/python-websockets/websockets/blob/d6b0a6203a24057c57a425834ea41acee0a7ea70/LICENSE)。固定 SHA 只锁定所读状态；[该提交本身](https://github.com/python-websockets/websockets/commit/d6b0a6203a24057c57a425834ea41acee0a7ea70)测试 uvloop 兼容性，不是 Origin 缺陷修复。握手规则依据 [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html)。本项目没有复制或改署名上游源码；本项目新写代码的 MIT [许可证](LICENSE)保存在「项目文档」，构建时复制到 Build 暂存源码并随包分发。故意弱化的本地基线不是上游漏洞或外部事件。

## 当前限制

此实现只服务于本地授权研究，不是完整 WebSocket 服务器或生产会话系统。预握手套接字读取期限为 2 秒；尚未设置并发连接数量上限。它不处理 TLS/WSS、HTTP/2 Extended CONNECT、代理转发、分片、多帧会话、扩展或复杂 Cookie 域策略。真实代理拓扑及 Host/Origin 转发规则仍为 OPEN。能伪造 Origin 且持有有效 Cookie 的非浏览器客户端仍可能通过策略，因此不得把 Origin 视为身份凭据。自有实验通过不证明 CVP 资格、真实任务受模型防护影响或外部部署安全。
