/* 大肥鱼远控 —— 客户端
 *
 * 当前是"占位实现"，目的是先把 GitHub Actions 的编译管道跑通：
 * 上传 → 云端编译 → 下载 APK → 手机能看到这个界面，就说明整条链路 OK。
 *
 * 真正的连接 / 配对 / 加密 / 会话逻辑随后接入（复用官方 @dsh-remote/protocol 包，
 * 不自己重写加密）。
 */

(function () {
  'use strict';

  var statusEl = document.getElementById('status');

  function setStatus(text, cls) {
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.className = cls || '';
  }

  setStatus('客户端开发中', 'muted');

  // TODO(后续接入):
  //   1. WebSocket 连接 wss://drc.provid.cc
  //   2. 发送 hello{role:'client', protocol:1}
  //   3. 收到 hello-ok 后，用 6 位配对码发 pair-begin-client
  //   4. 收到 paired 后用官方协议包做密钥派生 + 密封收发
  //   5. cmd.list_sessions / cmd.session_history / cmd.send_prompt
  //   6. 渲染 ev.session_changed / ev.message_delta / ev.run_state

})();
