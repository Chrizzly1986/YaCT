#-------------------------------------------------------------------------------
# YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
#-------------------------------------------------------------------------------
# Builds a self-contained YaCT application for Windows: a Java runtime with
# JavaFX built in, so users do not need to install Java.
#
# Usage: powershell -File packaging\package.ps1 [-Type app-image|msi|exe]
#   app-image (default): a runnable folder. msi/exe need the WiX Toolset on PATH.
# Result: target\dist\
param([string]$Type = "app-image")
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# JDK modules the application needs (determined with jdeps); jdk.localedata
# provides date and number formats for the translated languages.
$Modules = "java.base,java.naming,java.sql,jdk.localedata,jdk.charsets,javafx.controls"

$Version = ([xml](Get-Content pom.xml)).project.version
$AppVersion = $Version -replace '-SNAPSHOT$', ''

Write-Host "Building YaCT $Version ..."
mvn -B -q -DskipTests package
if ($LASTEXITCODE -ne 0) { throw "Maven build failed" }

$Target = "yact-ui\target"
$Stage = "$Target\jpackage-input"
$FxMods = "$Target\javafx-modules"
Remove-Item -Recurse -Force $Stage, $FxMods -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$Stage\lib", $FxMods, "target\dist" | Out-Null

Copy-Item "$Target\yact-ui-$Version.jar" $Stage
Get-ChildItem "$Target\lib\*.jar" | ForEach-Object {
    # JavaFX goes into the runtime as modules. Only the platform jars hold classes.
    if ($_.Name -match '^javafx-.*-win\.jar$') { Copy-Item $_.FullName $FxMods }
    elseif ($_.Name -notmatch '^javafx-') { Copy-Item $_.FullName "$Stage\lib" }
}

$ArgsList = @(
    "--type", $Type,
    "--icon", "packaging\icons\yact.ico",
    "--name", "YaCT",
    "--app-version", $AppVersion,
    "--vendor", "Christian Hoppe",
    "--copyright", "(c) 2015-2026 Christian Hoppe",
    "--description", "Encrypted file vault with post-quantum keys",
    "--input", $Stage,
    "--main-jar", "yact-ui-$Version.jar",
    "--main-class", "yact.ui.Launcher",
    "--module-path", $FxMods,
    "--add-modules", $Modules,
    "--jlink-options", "--strip-debug --no-header-files --no-man-pages --strip-native-commands --include-locales=en,de,fr,es,pt --compress=zip-6",
    "--java-options", "-Dfile.encoding=UTF-8",
    "--dest", "target\dist"
)
if ($Type -ne "app-image") {
    $ArgsList += @("--license-file", "Licence.txt", "--file-associations", "packaging\yact-file.properties",
                   "--win-menu", "--win-shortcut", "--win-dir-chooser", "--win-per-user-install")
}

Remove-Item -Recurse -Force "target\dist\YaCT" -ErrorAction SilentlyContinue
& jpackage @ArgsList
if ($LASTEXITCODE -ne 0) { throw "jpackage failed" }
Write-Host "Done: target\dist"
