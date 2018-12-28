#!/bin/bash

if [ -z "$1" ]
  then
    echo "Please supply build version (e.g. 2.0.1)"
    exit
fi

if [ -z "$2" ]
  then
    echo "Please supply notary id username (e.g. apple@example.com)"
    exit
fi

if [ -z "$3" ]
  then
    echo "Please supply notary id password (e.g. hunter2)"
    exit
fi


BUILD_VERSION="$1";
APPLE_UNAME="$2";
APPLE_PWORD="$3";


pushd /tmp/
rm -rf workspace || true
mkdir workspace
cd workspace
ln -s /Users/dannagle/github/cryptopp700 cryptopp700
git clone https://github.com/dannagle/Cryptoknife
cd Cryptoknife/src
#git checkout development

echo "Replacing globals.h with $BUILD_VERSION"
sed -i '' '/BEGIN/,/END/c\
#define SW_VERSION "v'$BUILD_VERSION'"
' globals.h

echo "Replacing Info.plist with $BUILD_VERSION"
sed -i '' 's/<string>1.0<\/string>/<string>'$BUILD_VERSION'<\/string>/' Info.plist

"/Users/dannagle/Qt/5.12.0/clang_64/bin/qmake" Cryptoknife.pro -spec macx-clang CONFIG+=x86_64
make
/Users/dannagle/Qt/5.12.0/clang_64/bin/macdeployqt Cryptoknife.app -appstore-compliant
codesign --option runtime --deep --force --sign "Developer ID Application: NagleCode, LLC (C77T3Q8VPT)" Cryptoknife.app

rm -rf /Users/dannagle/github/cryptoknife/Cryptoknife.app || true
mv Cryptoknife.app /Users/dannagle/github/Cryptoknife

rm -rf newbuild.dmg  || true
"/Applications/DMG Canvas.app/Contents/Resources/dmgcanvas" "/Users/dannagle/github/cryptoknife/Cryptoknife.dmgCanvas" newbuild.dmg

rm -rf /Users/dannagle/github/cryptoknife/Cryptoknife_v$BUILD_VERSION.dmg || true
mv newbuild.dmg /Users/dannagle/github/cryptoknife/Cryptoknife_v$BUILD_VERSION.dmg

echo "Finished creating Cryptoknife_v$BUILD_VERSION.dmg"

echo "Sending to Apple for notary"
xcrun altool --notarize-app -f /Users/dannagle/github/cryptoknife/Cryptoknife_v$BUILD_VERSION.dmg --primary-bundle-id 'com.cryptoknife.desktop'  -u ''$APPLE_UNAME'' -p ''$APPLE_PWORD''


popd
