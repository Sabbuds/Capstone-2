param([string]$JavaHome)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$previousPath = $env:PATH

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
$javaBin = Split-Path -Parent $compilerPath
$javaPath = Join-Path $javaBin 'java.exe'

Push-Location $repositoryRoot
try {
    $env:PATH = "$javaBin;$previousPath"
    $sources = @((Get-ChildItem src,samples -Filter '*.java' -Recurse).FullName)
    & $compilerPath -Xlint:all --release 17 -sourcepath 'src;samples' -d out $sources
    if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed.' }
    & $javaPath -cp out edu.fiu.capstone.skeleton.RegressionTests
    if ($LASTEXITCODE -ne 0) { throw 'Java regression tests failed.' }
    if (!(Get-Command node -ErrorAction SilentlyContinue) -or !(Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
        throw 'Node.js 20+ and npm are required for browser tests. Install Node.js LTS and rerun this command.'
    }
    if (!(Test-Path 'node_modules/playwright-core/package.json')) {
        & npm.cmd ci --ignore-scripts --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'Browser test dependency installation failed.' }
    }
    $previousJavaHome = $env:JAVA_HOME
    try {
        $env:JAVA_HOME = Split-Path -Parent $javaBin
        & npm.cmd run test:ui
        if ($LASTEXITCODE -ne 0) { throw 'Browser tests failed.' }
    } finally {
        $env:JAVA_HOME = $previousJavaHome
    }
    Write-Output 'All Java and browser suites passed. Runtime checks used harmless Java child processes.'
} finally {
    $env:PATH = $previousPath
    Pop-Location
}
