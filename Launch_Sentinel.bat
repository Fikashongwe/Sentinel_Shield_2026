@echo off
:: Set the interactive terminal window title for the admin session context
title Sentinel Security Interface

:: Change the working directory context directly to the script's path locations
cd /d "%~dp0"

:: Initialize the natively silent background security worker process
start sentinel_v2.exe