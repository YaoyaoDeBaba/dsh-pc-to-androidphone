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

# 序列帧自测要能读到真图集：临时拷一份到 tools/fish/（页面是 tools/，相对路径 fish/...），跑完删掉
$fishSrc = Join-Path $repo 'app/src/main/assets/fish'
$fishTmp = Join-Path $repo 'tools/fish'
$fishCopied = $false
if (Test-Path (Join-Path $fishSrc 'dafeiyu_Idle.webp')) {
  New-Item -ItemType Directory -Force -Path $fishTmp | Out-Null
  Copy-Item (Join-Path $fishSrc 'dafeiyu_Idle.webp') $fishTmp -Force
  if (Test-Path (Join-Path $fishSrc 'think.png')) { Copy-Item (Join-Path $fishSrc 'think.png') $fishTmp -Force }
  $fishCopied = $true
}

$tmp = Join-Path $env:TEMP ("drc-uitest-" + [guid]::NewGuid().ToString('N'))
$args = @(
  '--headless=new', '--disable-gpu', '--no-sandbox',
  '--allow-file-access-from-files',
  "--user-data-dir=$tmp",
  '--virtual-time-budget=15000',
  '--dump-dom',
  "file:///$($page -replace '\\', '/')"
)
$p = Start-Process -FilePath $browser -ArgumentList $args -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput "$tmp.out" -RedirectStandardError "$tmp.err"

$raw = Get-Content "$tmp.out" -Raw
$i = $raw.IndexOf('id="res"')
if ($i -lt 0) { Write-Error "页面里没有结果块（脚本没跑起来？）"; exit 1 }
# 窗口要够大：用例已经上百条，4000 字只能看到前一半，后面的失败会"看不见"（只体现在 title 的 FAIL:n 里）
$seg = $raw.Substring($i, [Math]::Min(30000, $raw.Length - $i))
$lines = ($seg -replace '</div>', "`n" -replace '<[^>]+>', '') -split "`n" |
  ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(PASS|FAIL) ' }

$lines | ForEach-Object { Write-Host $_ }
# 必须带空格：页面里可能混进 "failures: []" 这种以 fail 开头的文本，-like 'FAIL*' 会把它算成失败
$fails = @($lines | Where-Object { $_ -like 'FAIL *' }).Count
$title = ''
if ($raw -match '<title>(.*?)</title>') { $title = $matches[1]; Write-Host ("title=" + $title) }
# 页面标题是权威判据：任何 JS 异常也会让它变成 FAIL:n
if ($title -like 'FAIL*') { $fails = [Math]::Max($fails, 1) }
if ($seg -match 'class="bad">JS-ERRORS: ([^<]{0,300})') { Write-Host ('JS 异常：' + $matches[1]) }

# 静态检查：正式页面 index.html 的按钮摆位（自测页只是骨架，管不了正式页）
$html = Get-Content (Join-Path $repo 'app/src/main/assets/index.html') -Raw
$hStart = $html.IndexOf('<header>'); $hEnd = $html.IndexOf('</header>')
$headerBlock = if ($hStart -ge 0 -and $hEnd -gt $hStart) { $html.Substring($hStart, $hEnd - $hStart) } else { '' }
$menuStart = $html.IndexOf('id="menuWrap"')
$menuBlock = if ($menuStart -ge 0) { $html.Substring($menuStart, [Math]::Min(1200, $html.Length - $menuStart)) } else { '' }

$problems = @()
if ($headerBlock -notmatch 'id="gearBtn"') { $problems += '顶部没有齿轮按钮' }
foreach ($id in 'updateBtn', 'logToggleBtn', 'repairBtn') {
  if ($headerBlock -match "id=`"$id`"") { $problems += "$id 还留在顶部栏" }
  if ($menuBlock -notmatch "id=`"$id`"") { $problems += "$id 不在齿轮菜单里" }
}
if ($html -notmatch 'id="confirmWrap"') { $problems += '没有 5 秒确认框' }

if ($problems.Count) { $problems | ForEach-Object { Write-Host "FAIL $_" }; $fails += $problems.Count }
else { Write-Host 'PASS 正式页面：顶部只有齿轮，更新/日志/重新配对在菜单里，确认框齐全' }

Remove-Item "$tmp.out", "$tmp.err" -ErrorAction SilentlyContinue
if ($fishCopied) { Remove-Item $fishTmp -Recurse -Force -ErrorAction SilentlyContinue }
if ($fails -gt 0 -or $lines.Count -eq 0) { Write-Host "❌ $fails 项失败"; exit 1 }
Write-Host "✅ 全部通过（$($lines.Count + 1) 项）"
exit 0

