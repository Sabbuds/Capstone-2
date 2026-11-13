$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repositoryRoot '.benchmark-cache'
$revision = 'db99977cbf6b30236089a691136d718aa7bb6935'
$base = "https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/$revision"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "$base/expectedresults-1.2.csv" -OutFile (Join-Path $destination 'expectedresults-1.2.csv')
Invoke-WebRequest -UseBasicParsing -Uri "$base/LICENSE" -OutFile (Join-Path $destination 'LICENSE')
$labels = Get-Content (Join-Path $destination 'expectedresults-1.2.csv') |
    Where-Object { $_ -and !$_.StartsWith('#') } |
    ConvertFrom-Csv -Header Name,Category,Vulnerable,Cwe
$manifest = @()
foreach ($category in 'sqli','cmdi') {
    foreach ($truth in 'true','false') {
        $selected = @($labels | Where-Object { $_.Category -eq $category -and $_.Vulnerable -eq $truth } |
            Sort-Object Name | Select-Object -First 20)
        if ($selected.Count -ne 20) { throw 'Unexpected upstream benchmark labels.' }
        for ($i = 0; $i -lt $selected.Count; $i++) {
            $row = $selected[$i]
            $file = Join-Path $destination ($row.Name + '.java')
            Invoke-WebRequest -UseBasicParsing -Uri "$base/src/main/java/org/owasp/benchmark/testcode/$($row.Name).java" -OutFile $file
            $manifest += [pscustomobject]@{
                Name = $row.Name; Category = $category; Vulnerable = $truth; Cwe = $row.Cwe
                Split = $(if ($i -lt 15) { 'development' } else { 'validation' })
                Sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    }
}
# Fixed selection by upstream case ID, not by detector output; do not shuffle after seeing results.
$manifest | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $destination 'manifest.csv')
$support = Join-Path $destination 'support'
New-Item -ItemType Directory -Force -Path $support | Out-Null
$supportHashes = @()
foreach ($name in 'SeparateClassRequest','Thing1','Thing2','ThingFactory','ThingInterface','Utils') {
    $file = Join-Path $support "$name.java"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/src/main/java/org/owasp/benchmark/helpers/$name.java" -OutFile $file
    $supportHashes += [pscustomobject]@{ Name = "$name.java"; Sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$supportHashes | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $destination 'support.csv')
$resource = Join-Path $destination 'thing.properties'
Invoke-WebRequest -UseBasicParsing -Uri "$base/src/main/resources/thing.properties" -OutFile $resource
$resourceHashes = @([pscustomobject]@{ Name = 'thing.properties'; Sha256 = (Get-FileHash -LiteralPath $resource -Algorithm SHA256).Hash.ToLowerInvariant() })
foreach ($name in 'insecureCmd.sh','insecureCmd.bat') {
    $file = Join-Path $destination $name
    Invoke-WebRequest -UseBasicParsing -Uri "$base/src/main/resources/$name" -OutFile $file
    $resourceHashes += [pscustomobject]@{ Name = $name; Sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$resourceHashes | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $destination 'resources.csv')
Set-Content -Encoding UTF8 -Path (Join-Path $destination 'revision.txt') -Value $revision
Write-Output "Downloaded 80 original OWASP Benchmark 1.2 cases and six helper sources at $revision. First fifteen per group are development; next five are fresh validation."
