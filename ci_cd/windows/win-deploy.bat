echo Building Installers
set /p BUILD_VERSION=<buildversion.txt
set "BUILD_VERSION=%BUILD_VERSION: =%"
cd C:\Users\Dan\github\cryptoknifeinstaller\installer
move *.* ../archive
cd ..

"C:\Program Files\7-Zip\7z.exe" a CryptoknifePortable_v%BUILD_VERSION%.zip Cryptoknife
move CryptoknifePortable_v%BUILD_VERSION%.zip installer
