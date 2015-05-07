@echo off
REM *** Change this to your SpamAssassin program path
C:
CD \SpamAssassin

REM *** Uses standard spamd IP and port settings
CheckSpamd\t4eportping 127.0.0.1 783
IF "%ERRORLEVEL%"=="0" goto done

:startit
echo Starting spamd...
CheckSpamd\process.exe -k spamd.exe >NUL
REM *** Uses standard spamd IP and port settings. "log" directory should already exist
CheckSpamd\chp.exe spamd.exe -i 127.0.0.1 -s log\spamd.log --allow-tell

:done
