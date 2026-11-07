#-------------------------------------------------------------------------------
# YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
#-------------------------------------------------------------------------------
# Builds a self-contained YaCT application for Windows. See package.sh for the
# hardening; the same applies here.
#
# Usage: powershell -File packaging\package.ps1 [-Type app-image|msi|exe]
#   app-image (default): a runnable folder, also zipped. msi/exe need the WiX Toolset.
#   Installers install for all users into "Program Files", which other programs of
#   the user cannot modify.
# Result: target\dist\, with SHA256SUMS for every file produced.
param([string]$Type = "app-image")
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$ExtraModules = "jdk.localedata,jdk.charsets,jdk.crypto.ec"
$JavaOptions = "-Dyact.packaged=true -XX:+DisableAttachMechanism -XX:-CreateCoredumpOnCrash -XX:MaxRAMPercentage=50"

$Version = ([xml](Get-Content pom.xml)).project.version
$AppVersion = $Version -replace '-SNAPSHOT$', ''

Write-Host "Building YaCT $Version ..."
mvn -B -q -DskipTests package
if ($LASTEXITCODE -ne 0) { throw "Maven build failed" }

$Target = "yact-ui\target"
$Mods = "$Target\jpackage-modules"
Remove-Item -Recurse -Force $Mods, "target\dist" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Mods, "target\dist" | Out-Null

Copy-Item "$Target\yact-ui-$Version.jar" $Mods
Get-ChildItem "$Target\lib\*.jar" | ForEach-Object {
    # JavaFX: only the platform jars hold classes and native libraries.
    if ($_.Name -match '^javafx-.*-win\.jar$') { Copy-Item $_.FullName $Mods }
    elseif ($_.Name -notmatch '^javafx-') { Copy-Item $_.FullName $Mods }
}

& jpackage --type app-image `
    --name YaCT `
    --app-version $AppVersion `
    --vendor "Christian Hoppe" `
    --copyright "(c) 2015-2026 Christian Hoppe" `
    --description "Encrypted file vault with post-quantum keys" `
    --icon "packaging\icons\yact.ico" `
    --module-path $Mods `
    --module yact.ui/yact.ui.Launcher `
    --add-modules $ExtraModules `
    --jlink-options "--strip-debug --no-header-files --no-man-pages --strip-native-commands --include-locales=en,de,fr,es,pt --compress=zip-6 --ignore-signing-information" `
    --java-options $JavaOptions `
    --dest "target\dist"
if ($LASTEXITCODE -ne 0) { throw "jpackage failed" }

# JavaFX native libraries into the runtime's bin folder, where JavaFX loads them first
# (instead of extracting them to a user-writable cache).
$App = "target\dist\YaCT"
Add-Type -AssemblyName System.IO.Compression.FileSystem
Get-ChildItem "$Mods\javafx-graphics-*.jar" | ForEach-Object {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($_.FullName)
    try {
        $zip.Entries | Where-Object { $_.Name -like "*.dll" } | ForEach-Object {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, (Join-Path (Resolve-Path "$App\runtime\bin") $_.Name), $true)
        }
    } finally { $zip.Dispose() }
}

if ($Type -eq "app-image") {
    Compress-Archive -Path $App -DestinationPath "target\dist\YaCT-$AppVersion-windows.zip" -Force
} else {
    & jpackage --type $Type --app-image $App --name YaCT --app-version $AppVersion `
        --vendor "Christian Hoppe" --license-file Licence.txt `
        --file-associations "packaging\yact-file.properties" `
        --win-menu --win-shortcut --win-dir-chooser --dest "target\dist"
    if ($LASTEXITCODE -ne 0) { throw "jpackage failed" }
}

Get-ChildItem "target\dist" -File | Where-Object { $_.Name -ne "SHA256SUMS" } | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
} | Set-Content -Encoding ascii "target\dist\SHA256SUMS"
Write-Host "Done:"; Get-ChildItem "target\dist" | ForEach-Object { $_.Name }
