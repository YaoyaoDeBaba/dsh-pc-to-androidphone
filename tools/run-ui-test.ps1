# 手机端界面自测：用无头 Edge/Chrome 打开 tools/ui-test.html，把协议帧灌进
# app.js 的 applyEvent()，检查 DOM 是否按预期变化（不连真机、不连中继）。
#
#   pwsh -File tools/run-ui-test.ps1
#
# 退出码 0 = 全绿，1 = 有失败。

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$page = Join-Path $repo 'tools/ui-test.html'

$browsers = @(
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
)
$browser = $browsers | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) { Write-Error "没找到 Edge/Chrome，装一个再来"; exit 1 }

$tmp = Join-Path $env:TEMP ("drc-uitest-" + [guid]::NewGuid().ToString('N'))
$args = @(
  '--headless=new', '--disable-gpu', '--no-sandbox',
  '--allow-file-access-from-files',
  "--user-data-dir=$tmp",
  '--virtual-time-budget=5000',
  '--dump-dom',
  "file:///$($page -replace '\\', '/')"
)
$p = Start-Process -FilePath $browser -ArgumentList $args -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput "$tmp.out" -RedirectStandardError "$tmp.err"

$raw = Get-Content "$tmp.out" -Raw
$i = $raw.IndexOf('id="res"')
if ($i -lt 0) { Write-Error "页面里没有结果块（脚本没跑起来？）"; exit 1 }
$seg = $raw.Substring($i, [Math]::Min(4000, $raw.Length - $i))
$lines = ($seg -replace '</div>', "`n" -replace '<[^>]+>', '') -split "`n" |
  ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(PASS|FAIL)' }

$lines | ForEach-Object { Write-Host $_ }
$fails = @($lines | Where-Object { $_ -like 'FAIL*' }).Count
$title = ''
if ($raw -match '<title>(.*?)</title>') { $title = $matches[1]; Write-Host ("title=" + $title) }
# 页面标题是权威判据：任何 JS 异常也会让它变成 FAIL:n
if ($title -like 'FAIL*') { $fails = [Math]::Max($fails, 1) }
if ($seg -match 'class="bad">JS-ERRORS: ([^<]{0,300})') { Write-Host ('JS 异常：' + $matches[1]) }

# 静态检查：正式页面 index.html 的按钮摆位（自测页只是骨架，管不了正式页）
$html = Get-Content (Join-Path $repo 'app/src/main/assets/index.html') -Raw
$uiAt = $html.IndexOf('id="updateBtn"')
$logAt = $html.IndexOf('id="logToggleBtn"')
$h2At = $html.IndexOf('<h2>会话')
$h2End = $html.IndexOf('</h2>', [Math]::Max(0, $h2At))
if ($uiAt -lt 0) { Write-Host 'FAIL 正式页面没有 updateBtn'; $fails++ }
elseif ($uiAt -gt $h2At -and $h2At -ge 0 -and $uiAt -lt $h2End) { Write-Host 'FAIL 更新按钮还在会话标题栏里'; $fails++ }
elseif (-not ($logAt -gt $uiAt -and ($logAt - $uiAt) -lt 200)) { Write-Host 'FAIL 更新按钮没紧挨着日志按钮'; $fails++ }
else { Write-Host 'PASS 正式页面：更新按钮在顶部、紧挨日志' }

Remove-Item "$tmp.out", "$tmp.err" -ErrorAction SilentlyContinue
if ($fails -gt 0 -or $lines.Count -eq 0) { Write-Host "❌ $fails 项失败"; exit 1 }
Write-Host "✅ 全部通过（$($lines.Count + 1) 项）"
exit 0
