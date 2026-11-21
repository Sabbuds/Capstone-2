param([string]$JavaHome, [int]$Port = 8080, [string]$CommandProfile)
# Compiles the project and starts the local security scanner UI at http://localhost:$Port
# -CommandProfile linux-gnu-cat declares that scanned applications run GNU cat on Linux, which enables the
# command-injection repair. Without it, every command-injection finding is reported as needing a manual fix.
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot

if ($JavaHome) {
    $compilerPath = Join-Path $JavaHome 'bin\javac.exe'
} elseif (Get-Command javac -ErrorAction SilentlyContinue) {
    $compilerPath = (Get-Command javac).Source
} elseif ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\javac.exe'))) {
    $compilerPath = Join-Path $env:JAVA_HOME 'bin\javac.exe'
} else {
    $compilerPath = Get-ChildItem 'C:\Program Files\Java\*\bin\javac.exe' -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (!$compilerPath -or !(Test-Path -LiteralPath $compilerPath)) {
    throw 'A JDK 17+ is required. Pass -JavaHome with its installation directory.'
}
$javaPath = Join-Path (Split-Path -Parent $compilerPath) 'java.exe'

Push-Location $repositoryRoot
try {
    $sources = @((Get-ChildItem src,samples -Filter '*.java' -Recurse).FullName)
    & $compilerPath --release 17 -sourcepath 'src;samples' -d out $sources
    if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed.' }
    # Open the browser once the server has had a moment to start.
    $null = Start-Job -ScriptBlock { param($url) Start-Sleep -Seconds 2; Start-Process $url } -ArgumentList "http://localhost:$Port"
    $javaArgs = @()
    if ($CommandProfile) { $javaArgs += "-Dcapstone.target.commandProfile=$CommandProfile" }
    & $javaPath @javaArgs -cp out edu.fiu.capstone.ui.UiServer --port $Port
} finally {
    Pop-Location
}
