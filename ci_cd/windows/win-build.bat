echo Making exe
C:\Qt\5.12.0\mingw73_64\bin\qmake.exe -o Makefile src/Cryptoknife.pro -spec win32-g++
C:\Qt\Tools\mingw730_64\bin\mingw32-make.exe -f Makefile.Release
echo Signing exe
cd release
copy /Y C:\Users\Dan\Desktop\code_sign_exe_com.bat .
call code_sign_exe_com.bat
echo Copying signed exe
copy /Y Cryptoknife.exe C:\Users\Dan\github\cryptoknifeinstaller\Cryptoknife\Cryptoknife.exe
