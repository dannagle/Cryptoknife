#-------------------------------------------------
#
# Project created by QtCreator 2017-03-26T20:45:48
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Cryptoknife
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

# Yeah, yeah... I'm using 2 crypto libraries.
# crypto++ is easier to use


LIBS += -L$$PWD/../../cryptopp700/ -lcryptopp
PRE_TARGETDEPS += $$PWD/../../cryptopp700/libcryptopp.a

INCLUDEPATH += $$PWD/../../cryptopp700
DEPENDPATH += $$PWD/../../cryptopp700


macx:ICON = ckicons.icns


win32:RC_FILE = ckicon.rc

SOURCES += main.cpp\
        mainwindow.cpp \
    crypto.cpp \
    brucethepoodle.cpp \
    crc32.cpp

HEADERS  += mainwindow.h \
    crypto.h \
    globals.h \
    brucethepoodle.h \
    crc32.h



FORMS    += mainwindow.ui \
    brucethepoodle.ui

RESOURCES += \
    cryptokniferes.qrc
