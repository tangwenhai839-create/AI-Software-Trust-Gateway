param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$distRoot = Join-Path $projectRoot 'dist'
$appStage = Join-Path $distRoot 'windows-app'
$pyinstallerDist = Join-Path $distRoot 'pyinstaller'
$pyinstallerWork = Join-Path $projectRoot 'build\pyinstaller'

function Remove-ProjectDirectory([string]$PathToRemove) {
    $fullTarget = [System.IO.Path]::GetFullPath($PathToRemove)
    $fullProject = [System.IO.Path]::GetFullPath($projectRoot).TrimEnd('\') + '\'
    if (-not $fullTarget.StartsWith($fullProject, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the project: $fullTarget"
    }
    if (Test-Path -LiteralPath $fullTarget) {
        Remove-Item -LiteralPath $fullTarget -Recurse -Force
    }
}

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
Remove-ProjectDirectory $appStage
Remove-ProjectDirectory $pyinstallerDist
Remove-ProjectDirectory $pyinstallerWork
New-Item -ItemType Directory -Force -Path $pyinstallerWork | Out-Null

Write-Host '[1/4] Building the production Web interface...'
Push-Location (Join-Path $projectRoot 'frontend')
try {
    $env:NEXT_PUBLIC_API_URL = 'http://127.0.0.1:8000/api/v1'
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Next.js build failed' }
}
finally {
    Pop-Location
}

Write-Host '[2/4] Building the self-contained Windows backend...'
Push-Location $projectRoot
try {
    pyinstaller --noconfirm --clean --windowed --onedir `
        --name ASTG `
        --paths $projectRoot `
        --distpath $pyinstallerDist `
        --workpath $pyinstallerWork `
        --specpath $pyinstallerWork `
        --add-data "$projectRoot\rules;rules" `
        --add-data "$projectRoot\schemas;schemas" `
        --add-data "$projectRoot\fixtures;fixtures" `
        --hidden-import backend.app.db.models `
        --hidden-import aiosqlite `
        --collect-all aiosqlite `
        --collect-submodules uvicorn `
        --collect-submodules sqlalchemy.dialects.sqlite `
        desktop\launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
}
finally {
    Pop-Location
}

Write-Host '[3/4] Assembling bundled Node.js and frontend files...'
New-Item -ItemType Directory -Force -Path $appStage | Out-Null
Copy-Item -Path (Join-Path $pyinstallerDist 'ASTG\*') -Destination $appStage -Recurse -Force

$runtimeDir = Join-Path $appStage 'runtime'
$frontendDir = Join-Path $appStage 'frontend'
New-Item -ItemType Directory -Force -Path $runtimeDir, $frontendDir | Out-Null
$nodePath = (Get-Command node -ErrorAction Stop).Source
Copy-Item -LiteralPath $nodePath -Destination (Join-Path $runtimeDir 'node.exe') -Force
Copy-Item -Path (Join-Path $projectRoot 'frontend\.next\standalone\*') -Destination $frontendDir -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $frontendDir '.next\static') | Out-Null
Copy-Item -Path (Join-Path $projectRoot 'frontend\.next\static\*') -Destination (Join-Path $frontendDir '.next\static') -Recurse -Force
Copy-Item -Path (Join-Path $projectRoot 'frontend\public') -Destination $frontendDir -Recurse -Force

if ($SkipInstaller) {
    Write-Host "Application staging completed: $appStage"
    exit 0
}

Write-Host '[4/4] Compiling the one-click installer...'
$isccCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
)
$iscc = $isccCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $iscc) {
    throw 'Inno Setup 6 was not found. Install JRSoftware.InnoSetup and rerun this script.'
}
& $iscc (Join-Path $PSScriptRoot 'astg.iss')
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed' }

$installer = Get-ChildItem (Join-Path $distRoot 'installer\AI-Software-Trust-Gateway-Setup-*.exe') |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
Write-Host "Installer completed: $($installer.FullName)"
