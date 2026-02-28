@echo off
REM Run all tests for SecureComm on Windows

echo =====================================
echo SecureComm Test Suite
echo =====================================
echo.

echo Running shared library tests...
cd shared
cargo test --lib --tests 2>&1
cd ..

echo.
echo Running server tests...
cd server
cargo test --lib --tests 2>&1
cd ..

echo.
echo =====================================
echo Test Suite Complete
echo =====================================
pause