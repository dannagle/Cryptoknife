/*
 * This file is part of Cryptoknife
 *
 * Licensed GPL v2
 * http://Cryptoknife.com/
 *
 * Copyright Dan Nagle
 *
 */

#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
