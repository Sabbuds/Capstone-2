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
    foreach ($suite in 'SqliDetectionTest','CommandInjectionTest','DetectorContractTest','SqliRepairTest','SecurityIntegrationTest','DetectionEvaluationTest') {
        & $javaPath -cp out "edu.fiu.capstone.skeleton.$suite"
        if ($LASTEXITCODE -ne 0) { throw "$suite failed." }
    }
    & $javaPath -cp out edu.fiu.capstone.skeleton.DetectionEvaluation
    if ($LASTEXITCODE -ne 0) { throw 'Development corpus evaluation failed.' }
    Write-Output 'All security suites passed. Sample command methods were not executed.'
} finally {
    $env:PATH = $previousPath
    Pop-Location
}
