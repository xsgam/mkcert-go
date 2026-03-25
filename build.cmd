@echo off
echo Building MKCert...
go build -o MKCert.exe main.go
if %ERRORLEVEL% EQU 0 (
    echo Build successful: MKCert.exe
) else (
    echo Build failed!
    exit /b 1
)