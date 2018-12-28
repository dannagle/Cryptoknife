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
#include "ui_mainwindow.h"

#include "crypto.h"


#include <QFileDialog>
#include <QDebug>

#include <QDragEnterEvent>
#include <QDragLeaveEvent>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QList>
#include <QDirIterator>
#include <QTabWidget>
#include <QPushButton>
#include <QDesktopServices>
#include <QElapsedTimer>
#include <QShortcut>
#include <QCryptographicHash>
#include <QSysInfo>
#include <QProcess>
#include <QStorageInfo>
#include <QFileInfoList>
#include <QClipboard>
#include <QSettings>
#include <QStandardPaths>

#include <QNetworkInterface>
#include <QHostAddress>
#include <QAbstractSocket>
#include <QNetworkAddressEntry>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QMessageBox>

#include "crc32.h"

#include "globals.h"
#include "brucethepoodle.h"

#ifdef __WIN32

#include <windows.h>
#include <intrin.h>

#endif

#ifdef __APPLE__
#define SETTINGSFILE QStandardPaths::writableLocation( QStandardPaths::GenericDataLocation )+ "/com.cryptoknife/cryptoknife_settings.ini"
#else
#define SETTINGSFILE "cryptoknife_settings.ini"
#endif
#define SETLOG(var) ui->resultTextEdit->clear(); appendResult(var);


#ifdef __APPLE__
#define LOGFILE QStandardPaths::writableLocation(QStandardPaths::DownloadLocation) + "/cryptoknife.log"
#else
#define LOGFILE "cryptoknife.log"
#endif
#define SETLOG(var) ui->resultTextEdit->clear(); appendResult(var);



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setWindowTitle("Cryptoknife");

    ui->menuBar->hide();
    ui->mainToolBar->hide();

    setAcceptDrops(true);

    ui->mainTabWidget->setCurrentIndex(0);

    ui->encryptTabWidget->setCurrentIndex(0);

    ui->resultTextEdit->setAcceptDrops(false);

    ui->progressBar->hide();
    ui->cancelButton->hide();

    QIcon mIcon("://logo.png");
    setWindowIcon(mIcon);

    //default checked
    ui->md5Check->setChecked(true);
    ui->sha1Check->setChecked(true);
    ui->sha256Check->setChecked(true);

    ui->resultTextEdit->setReadOnly(true);
    ui->resultTextEdit->setWordWrapMode(QTextOption::NoWrap);


        //Bruce is my pet poodle.
        //Dog easter egg.  CTRL D, O, G.
        //             or  CMD D, O, G.
    QShortcut *bruce = new QShortcut(QKeySequence(Qt::CTRL + Qt::Key_D,Qt::CTRL + Qt::Key_O, Qt::CTRL + Qt::Key_G ), this);

    if(!connect(bruce, &QShortcut::activated, this, &MainWindow::poodlepic)) {
        QDEBUG() << "bruce connection false";
    }



    QString systemInfo = systemProfile();

    SETLOG(systemInfo);

    systemInfo.prepend("<b style='color:green'>Drag &amp; Drop files and directories here.</b><hr>\n");
    systemInfo.replace("\n", "<br>");
    ui->resultTextEdit->setText(systemInfo);



    generateUrlButton("@NagleCode", "https://twitter.com/NagleCode");
    generateUrlButton("Cryptoknife.com", "http://cryptoknife.com/");
    //generateUrlButton("PacketSender.com", "http://packetsender.com/");


    epochedit = true;

    QDateTime now = QDateTime::currentDateTime();

    ui->dateTimeEdit->setDateTime(now);
    ui->epochEdit->setText(QString::number(now.toSecsSinceEpoch()));
    epochedit = false;

    asciiedit = false;

    directHash = false;

    cancel = false;


    passwordedit = true;
    ui->secureLengthCombo->clear();
    for(int i=5; i<=30; i++) {
        ui->secureLengthCombo->addItem(QString::number(i));
    }
    ui->secureLengthCombo->setCurrentIndex(ui->secureLengthCombo->findText("15"));
    qsrand(static_cast<uint>(QTime::currentTime().msec()));
    passwordedit = false;

    on_genSecurePWButton_clicked();

    logbuttondisplay();

    statusBar()->showMessage("Version : " SW_VERSION, 3000);

    if(QFile::exists(SETTINGSFILE)) {
        processSettings(false);
    }

}

void MainWindow::logbuttondisplay()
{

    QFileInfo check_file(LOGFILE);

    qint64 filesize = check_file.size();
    QString deletetext = "Delete log (";
    ui->deleteFileButton->setText(deletetext + QString::number(filesize) + " Bytes)");
    if(filesize > (1000)) {
        ui->deleteFileButton->setText(deletetext + QString::number(filesize / (1000)) + " KB)");
    }
    if(filesize > (1000 * 1000)) {
        ui->deleteFileButton->setText(deletetext + QString::number(filesize / (1000*1000)) + " MB)");
    }
    if(filesize > (1000 * 1000*1000)) {
        ui->deleteFileButton->setText(deletetext + QString::number(filesize / (1000*1000*1000)) + " GB)");
    }

}

void MainWindow::poodlepic()
{
    QDEBUG();

    BruceThePoodle *bruce = new BruceThePoodle(this);
    bruce->show();
}


void MainWindow::generateUrlButton(QString name, QString link)
{

    static int buttonindex = 0;

    QString hyperLinkStyle = "QPushButton { color: blue; } QPushButton::hover { color: #BC810C; } ";


    QPushButton * linkButton = new QPushButton(name);
    linkButton->setStyleSheet(hyperLinkStyle);
    linkButton->setFlat(true);
    linkButton->setProperty("link", link);
    linkButton->setCursor(Qt::PointingHandCursor);

    if(!connect(linkButton, &QPushButton::clicked, this, &MainWindow::launchBrowser)) {
        QDEBUG() << "field1 connection false";
    }

    buttonindex = statusBar()->insertPermanentWidget(buttonindex, linkButton);
    buttonindex++;

}

void MainWindow::dragEnterEvent(QDragEnterEvent* event)
{
  // if some actions should not be usable, like move, this code must be adopted
    //QDEBUG();
  event->acceptProposedAction();
}

void MainWindow::dragMoveEvent(QDragMoveEvent* event)
{
  // if some actions should not be usable, like move, this code must be adopted
    //QDEBUG();
  event->acceptProposedAction();
}

void MainWindow::dragLeaveEvent(QDragLeaveEvent* event)
{
    //QDEBUG();
  event->accept();
}




QString MainWindow::doCrypto(QString filename)
{

    Crypto crypto;
    crypto.filename = filename;
    crypto.domd2 = ui->md2Check->isChecked();
    crypto.domd4 = ui->md4Check->isChecked();
    crypto.doMD5 = ui->md5Check->isChecked();
    crypto.dosha1 = ui->sha1Check->isChecked();
    crypto.dosha224 = ui->sha224Check->isChecked();
    crypto.dosha256 = ui->sha256Check->isChecked();
    crypto.dosha384 = ui->sha384Check->isChecked();
    crypto.dosha512 = ui->sha512Check->isChecked();

    appendResult("File: " + filename);

    crypto.doHash();


    if(ui->checksum8Check->isChecked()) {
        quint64 chksum = Crypto::Checksum(filename);
        appendResult("Checksum: " + QString::number(chksum, 16).toUpper());
    }

    if(ui->crc32Check->isChecked()) {
        Crc32 crc32;
        quint32 crcresult = crc32.calculateFromFile(filename);
        appendResult("CRC32: " + QString::number(crcresult, 16));
    }

    if(ui->base64DecCheck->isChecked()) {
        QString newFile = filename + ui->base64DecExtEdit->text();
        QDEBUGVAR(newFile);
        Crypto::Base64Decode(filename.toStdString().c_str(), newFile.toStdString().c_str());
        appendResult("Base64 Decoded to:" + newFile);
    }

    if(ui->base64EncCheck->isChecked()) {
        QString newFile = filename + ui->base64ExtEdit->text();
        Crypto::Base64Encode(filename.toStdString().c_str(), newFile.toStdString().c_str());
        appendResult("Base64 Encoded to:" + newFile);
    }

    if(ui->hexCheck->isChecked()) {
        QString newFile = filename + ui->hexExtEdit->text();
        crypto.Bin2HEX(filename.toStdString().c_str(), newFile.toStdString().c_str());
        appendResult("Bin2HEX to:" + newFile);
    }

    if(ui->binCheck->isChecked()) {
        QString newFile = filename + ui->binExtEdit->text();
        crypto.HEX2Bin(filename.toStdString().c_str(), newFile.toStdString().c_str());
        appendResult("HEX2Bin to:" + newFile);
    }


    if(ui->dos2UnixCheck->isChecked()) {
        QFile dos2unixFile(filename);

        if(dos2unixFile.open(QFile::ReadOnly)) {
            QByteArray theData = dos2unixFile.readAll();
            dos2unixFile.close();

            bool isBinary = false;
            if(ui->ignoreBinaryCheck->isChecked()) {
                for(int i = 0; i < theData.size(); ++i) {
                    if(((unsigned char) theData.at(i)) > 127) {
                        isBinary = true;
                        break;
                    }
                }
                if(isBinary) {
                    appendResult("Skipping non-ASCII file");
                }
            }

            if(!isBinary) {

                int oldSize = theData.size();
                if(ui->dos2UnixRadio->isChecked()) {
                    appendResult("Converting DOS to Unix");
                    theData.replace("\r", "");
                } else {
                    appendResult("Converting Unix to DOS");
                    theData.replace("\r", "");  //remove solitary carriage returns
                    theData.replace("\n", "\r\n");
                }
                int newSize = theData.size();
                if(dos2unixFile.open(QFile::WriteOnly)) {
                    dos2unixFile.write(theData);
                    dos2unixFile.close();
                    appendResult("Old size:" + QString::number(oldSize) + ", New size:" + QString::number(newSize));


                }

            }

        }
    }

    if(ui->tripleDESCheck->isChecked()) {
        crypto.tripleDESKey = ui->tripleDESKeyEdit->text().trimmed().toUpper();
        crypto.tripleDESIV = ui->tripleDESIVEdit->text().trimmed().toUpper();
        if(ui->encryptDESRadio->isChecked()) {
            if(ui->tripleDESVariantCombo->currentText().contains("2")) {
                crypto.TripleDES2_CBC_Encrypt(QString(crypto.filename + ".des-ede-cbc").toStdString().c_str());
            } else {
                crypto.TripleDES3_CBC_Encrypt(QString(crypto.filename + ".des-ede3-cbc").toStdString().c_str());
            }

            appendResult("key:" + crypto.tripleDESKey);
            appendResult("IV:" + crypto.tripleDESIV);
        }

        if(ui->decryptDESRadio->isChecked()) {

            if(ui->tripleDESVariantCombo->currentText().contains("2")) {
                crypto.TripleDES2_CBC_Decrypt(QString(crypto.filename + ".decrypted").toStdString().c_str());
            } else {
                crypto.TripleDES3_CBC_Decrypt(QString(crypto.filename + ".decrypted").toStdString().c_str());
            }
            appendResult("Decrypting file:" + crypto.filename);
        }

    }

    if(ui->blowfishCheck->isChecked()) {
        crypto.blowfishKey = ui->bfKeyEdit->text().trimmed().toUpper();
        crypto.blowfishIV = ui->bfIVEdit->text().trimmed().toUpper();
        if(ui->encryptBlowfishRadio->isChecked()) {
            crypto.Blowfish_CBC_Encrypt(QString(crypto.filename + ".blowfish-cbc").toStdString().c_str());
            appendResult("key:" + crypto.blowfishKey);
            appendResult("IV:" + crypto.blowfishIV);

        }

        if(ui->decryptBlowfishRadio->isChecked()) {
            crypto.Blowfish_CBC_Decrypt(QString(crypto.filename + ".decrypted").toStdString().c_str());
            appendResult("Decrypting file:" + crypto.filename);
        }

    }


    if(ui->twofishCheck->isChecked()) {
        crypto.twofishKey = ui->key2FishEdit->text().trimmed().toUpper();
        crypto.twofishIV = ui->iv2FishEdit->text().trimmed().toUpper();
        if(ui->encrypt2FishRadio->isChecked()) {
            crypto.Twofish_CBC_Encrypt(QString(crypto.filename + ".2fish-cbc").toStdString().c_str());
            appendResult("key:" + crypto.twofishKey);
            appendResult("IV:" + crypto.twofishIV);

        }

        if(ui->decrypt2FishRadio->isChecked()) {
            crypto.Twofish_CBC_Decrypt(QString(crypto.filename + ".decrypted").toStdString().c_str());
            appendResult("Decrypting file:" + crypto.filename);
        }

    }


    if(ui->aesCheck->isChecked()) {

        QString bitcheck = ui->aesBitsCombo->currentText().split(" ").first();
        crypto.aesBits = bitcheck.toInt();
        crypto.aesKey = ui->keyEdit->text().trimmed().toUpper();
        crypto.aesIV = ui->ivEdit->text().trimmed().toUpper();

        if(ui->encryptAESRadio->isChecked()) {
            QString newFileExt = ".aes-" + QString::number(crypto.aesBits) + "-cbc";
            crypto.AES_CBC_Encrypt(QString(crypto.filename + newFileExt).toStdString().c_str());
            appendResult("key:" + crypto.aesKey);
            appendResult("IV:" + crypto.aesIV);

        }

        if(ui->decryptAESRadio->isChecked()) {
            crypto.AES_CBC_Decrypt(QString(crypto.filename + ".decrypted").toStdString().c_str());
            appendResult("Decrypting file:" + crypto.filename);
        }


    }
    return crypto.result;

}

void MainWindow::appendResult(QString result)
{
    if(result.isEmpty()) return;

    if(ui->saveDownloadsLogCheck->isChecked()) {
        QFile logFile(LOGFILE);
        if(logFile.open(QFile::Append)) {
            logFile.write(QString("\r\n" + result).toLatin1());
            logFile.close();
            logbuttondisplay();
        }
    }


    QString currentText = ui->resultTextEdit->toPlainText();
    ui->resultTextEdit->setText(currentText + "\n" + result.trimmed());
}


void MainWindow::processSettings(bool save)
{
    QCheckBox * checkbox;
    QLineEdit * lineedit;
    QComboBox * combo;
    QRadioButton * radio;
    QTextEdit * text;

    QSettings settings(SETTINGSFILE, QSettings::IniFormat);
    QList<QCheckBox *> checkboxes = ui->centralWidget->findChildren<QCheckBox *>();
    QList<QLineEdit *> lineedits = ui->encodingGroupBox->findChildren<QLineEdit *>();
    QList<QComboBox *> combos = ui->centralWidget->findChildren<QComboBox *>();
    QList<QRadioButton *> radios = ui->centralWidget->findChildren<QRadioButton *>();
    QList<QTextEdit *> texts = ui->mainTabWidget->findChildren<QTextEdit *>();



    foreach(checkbox, checkboxes) {
        if(save) {
            settings.setValue(checkbox->objectName(), checkbox->isChecked());
        } else {
            checkbox->setChecked(settings.value(checkbox->objectName(), false).toBool());
        }
    }

    foreach(combo, combos) {
        if(save) {
            settings.setValue(combo->objectName(), combo->currentText());
        } else {
            QString value = settings.value(combo->objectName(), "").toString();
            int index = combo->findText(value);
            if(index > -1) {
                combo->setCurrentIndex(index);
            }

        }
    }

    foreach(radio, radios) {
        if(save) {
            settings.setValue(radio->objectName(), radio->isChecked());
        } else {
            radio->setChecked(settings.value(radio->objectName(), false).toBool());
        }
    }

    foreach(lineedit, lineedits) {
        if(save) {
            settings.setValue(lineedit->objectName(), lineedit->text());
        } else {
            lineedit->setText(settings.value(lineedit->objectName(), "").toString());
        }
    }

    foreach(text, texts) {
        if(save) {
            settings.setValue(text->objectName(), text->toPlainText());
        } else {
            text->setText(settings.value(text->objectName(), "").toString());
        }
    }


}


void MainWindow::launchBrowser()
{

    QObject* obj = sender();
    QString link = obj->property("link").toString();
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::dropEvent(QDropEvent* event)
{

    ui->resultTextEdit->clear();
    QStringList filePathList;
    if (event->mimeData()->hasUrls())
    {
        foreach (QUrl url, event->mimeData()->urls())
        {
            filePathList << url.toLocalFile();
        }
    }

    QDEBUG() << filePathList;

    QString file, hashFile;
    foreach(file, filePathList) {

        QStringList iterateList;iterateList.clear();

        QFileInfo check_file(file);

        if(check_file.exists() && check_file.isDir()) {
            QDirIterator it(file, QDirIterator::Subdirectories);
            while (it.hasNext()) {
                QString fileString = it.next();
                QFileInfo check_file2(fileString);
                if(check_file2.exists() && check_file2.isFile()) {
                    iterateList << fileString;
                }
            }
        } else {

            if(check_file.exists() && check_file.isFile()) {
                iterateList << file;
            }
        }


        QElapsedTimer timer;
        timer.start();
        ui->progressBar->setValue(0);
        ui->progressBar->setMinimum(0);
        ui->progressBar->setMaximum(iterateList.size());
        ui->progressBar->show();
        ui->cancelButton->show();
        cancel = false;

        for(int index=0; index<iterateList.size(); index++) {

            hashFile = iterateList[index];
            ui->progressBar->setValue(index);
            QApplication::processEvents();
            appendResult(doCrypto(hashFile));

            if(cancel) {
                appendResult("Progress cancelled.");
                break;
            }

        }

        ui->progressBar->hide();
        ui->cancelButton->hide();
        cancel = false;
        appendResult("Finished in " + QString::number(timer.elapsed()) + " milliseconds.");


    }


}


MainWindow::~MainWindow()
{

    processSettings(true);
    delete ui;
}

bool MainWindow::openFiles(const QStringList &pathList)
{
    QDEBUG() << pathList;

    return true;
}

void MainWindow::on_epochEdit_textEdited(const QString &arg1)
{
    if(epochedit) return;
    epochedit = true;
    qint64 newtime = arg1.toLong();
    QDateTime newnow;
    newnow.setSecsSinceEpoch(newtime);
    ui->dateTimeEdit->setDateTime(newnow);
    epochedit = false;

}

void MainWindow::on_dateTimeEdit_dateTimeChanged(const QDateTime &dateTime)
{
    if(epochedit) return;
    epochedit = true;
    ui->epochEdit->setText(QString::number(dateTime.toSecsSinceEpoch()));
    epochedit = false;
}


int hexToInt(QChar hex)
{
    hex = hex.toLower();

    if(hex == 'f')
    {
        return 15;
    }
    if(hex == 'e')
    {
        return 14;
    }
    if(hex == 'd')
    {
        return 13;
    }
    if(hex == 'c')
    {
        return 12;
    }
    if(hex == 'b')
    {
        return 11;
    }
    if(hex == 'a')
    {
        return 10;
    }

    return hex.digitValue();

}

QString ASCIITohex(QString &ascii)
{
    if(ascii.isEmpty())
    {
        return "";
    }

    QString asciiText = ascii;
    QString hexText = "";
    QChar tempChar1, tempChar2;
    QChar charTest;
    QString convertTest;
    bool msb = false;
    bool lsb = false;
    int lsbInt = 0;
    int msbInt = 0;

    // qDebug() << __FILE__ << "/" << __LINE__;

    //convert special sequences to raw numbers.
    asciiText.replace("\\\\", "\\" + QString::number('\\', 16));
    asciiText.replace("\\n", "\\0" + QString::number('\n', 16));
    asciiText.replace("\\r", "\\0" + QString::number('\r', 16));
    asciiText.replace("\\t", "\\0" + QString::number('\t', 16));

    // qDebug() << __FILE__ << "/" << __LINE__;
    if(asciiText.size() > 0)
    {
        if(asciiText.at(asciiText.size()-1) == '\\') //last char is a slash
        {
            asciiText.append("00");
        }
    }

    // qDebug() << __FILE__ << "/" << __LINE__;
    if(asciiText.size() > 2)
    {
        if(asciiText.at(asciiText.size()-2) == '\\') //second last char is a slash
        {
            //slide 0 in between

            // qDebug() << __FILE__ << "/" << __LINE__ <<"second last is slash";

            charTest = asciiText.at(asciiText.size()-1);
            asciiText[asciiText.size()-1] = '0';
            asciiText.append(charTest);
        }
    }
    // qDebug() << __FILE__ << "/" << __LINE__ <<"analyze" << asciiText;


    for (int i = 0 ; i < asciiText.size(); i++)
    {
        msb = false;
        lsb = false;
        lsbInt = 0;
        msbInt = 0;

        charTest = asciiText.at(i);

        // qDebug() << __FILE__ << "/" << __LINE__ <<"checking" << charTest;

        if(charTest == '\\')
        {
            // qDebug() << __FILE__ << "/" << __LINE__ <<"found slash";
            if(i + 1 < asciiText.size())
            {
                msbInt = hexToInt(asciiText.at(i + 1));
                if(msbInt > -1)
                {
                    msb = true;
                }
                // qDebug() << __FILE__ << "/" << __LINE__ <<"msb convert test is" << msb;

            }
            if(i + 2 < asciiText.size())
            {
                lsbInt = hexToInt(asciiText.at(i + 2));
                if(lsbInt > -1)
                {
                    lsb = true;
                }
                // qDebug() << __FILE__ << "/" << __LINE__ <<"lsb convert test is" << lsb;
            }

            if(msb)
            {
                hexText.append(QString::number(msbInt, 16));
                // qDebug() << __FILE__ << "/" << __LINE__ <<"hexText append result" << hexText;
                i++;
            }

            if(lsb)
            {
                hexText.append(QString::number(lsbInt, 16));
                // qDebug() << __FILE__ << "/" << __LINE__ <<"hexText append" << hexText;
                i++;
            }

        } else {
            // qDebug() << __FILE__ << "/" << __LINE__ <<"no slash";
            lsbInt = ((int) charTest.toLatin1()) & 0xff;
            if(lsbInt > 0 && lsbInt < 16)
            {
                hexText.append("0");
            }
            hexText.append(QString::number(lsbInt, 16));
            // qDebug() << __FILE__ << "/" << __LINE__ <<"appended lsbInt:" << QString::number(lsbInt, 16);
        }

        hexText.append(" ");
        // qDebug() << __FILE__ << "/" << __LINE__ <<"hex test now " << hexText;

    }

    return hexText;

}


QString hexToASCII(QString &hex)
{


    QStringList hexSplit;

    //remove invalid characters of popular deliminators...
    hex = hex.replace(",", " ");
    hex = hex.replace(".", " ");
    hex = hex.replace(":", " ");
    hex = hex.replace(";", " ");
    hex = hex.replace("0x", " ");
    hex = hex.replace("x", " ");
    hex = hex.replace("\n", " ");
    hex = hex.replace("\r", " ");
    hex = hex.replace("\t", " ");

    QString hexText = hex.simplified();
    if(hexText.isEmpty())
    {
        return "";
    }

    if((hexText.size() % 2 != 0)) {
        //Not divisible by 2. What should I do?
        if(!hexText.contains(" ") && hexText.size() > 2)
        {
            //Seems to be one big hex stream. Front-load it with a 0.
            hexText.prepend("0");
        }

    }


    if(!hexText.contains(" ") && hexText.size() > 2 && hexText.size() % 2 == 0)
    {
        //does not contain any spaces.  Maybe one big hex stream?
        QDEBUG() << "no spaces" << "even digits";
        QStringList hexList;
        hexList.clear();
        QString append;
        append.clear();
        for(int i =0; i < hexText.size(); i+=2)
        {
            append.clear();
            append.append(hexText[i]);
            append.append(hexText[i + 1]);
            hexList << append;
        }
        hexText = hexList.join(" ").trimmed();
        hex = hexText;
    }

    hexSplit = hexText.split(" ");
    QString asciiText = "";
    unsigned int convertInt;
    bool ok = false;
    int malformed = 0;
    bool malformedBool = false;
    QChar malformedChar;


    QString checkSpace = hex.at(hex.size() - 1);
    if(checkSpace == " ")
    {
        hexText.append(" ");
    }

    hex = hexText;

    // qDebug() << __FILE__ << "/" << __LINE__  << __FUNCTION__ <<"analyze hex split" << hexSplit;

    for(int i=0; i< hexSplit.size(); i++)
    {
        if(hexSplit.at(i).size() > 2)
        {
            malformedBool = true;
            malformed = i;
            malformedChar = hexSplit.at(i).at(2);
            // qDebug() << __FILE__ << "/" << __LINE__ << __FUNCTION__  << "malformed at"<< QString::number(i) << "is" << malformedChar;
            break;
        }

    }

    if(malformedBool)
    {
        QString fixText = "";
        QString testChar;

        for(int i = 0; i < malformed; i++)
        {
            fixText.append(hexSplit.at(i));
            fixText.append(" ");
        }


        testChar.append(malformedChar);
        testChar.toUInt(&ok, 16);

        // qDebug() << __FILE__ << "/" << __LINE__  << __FUNCTION__ << "malformed digitvalue" << malformedChar.digitValue();

        if(ok)
        {
            fixText.append(hexSplit.at(malformed).at(0));
            fixText.append(hexSplit.at(malformed).at(1));
            fixText.append(" ");
            fixText.append(malformedChar);
        }
        hexText = (fixText.simplified());
        hex = hexText;
        hexSplit = hexText.split(" ");
    }



    for(int i=0; i< hexSplit.size(); i++)
    {
        convertInt = hexSplit.at(i).toUInt(&ok, 16);
        // qDebug() << __FILE__ << "/" << __LINE__ << __FUNCTION__  <<"hex at"<< QString::number(i) << "is" << QString::number(convertInt);
        if(ok)
        {
            if(convertInt >= 0x20 && convertInt <= 0x7e && convertInt != '\\')
            {
                // qDebug() << __FILE__ << "/" << __LINE__  << __FUNCTION__ << "Converted to " << QChar(convertInt);
                asciiText.append((QChar(convertInt)));
            } else {
                asciiText.append("\\");
                switch((char)convertInt)
                {
                case '\n':
                    asciiText.append("n");
                    break;
                case '\r':
                    asciiText.append("r");
                    break;
                case '\t':
                    asciiText.append("t");
                    break;
                case '\\':
                    asciiText.append("\\");
                    break;
                default:
                    if(convertInt < 16)
                    {
                        asciiText.append("0");
                    }
                    asciiText.append(QString::number(convertInt, 16));
                    break;

                }

            }

        } else {
            // qDebug() << __FILE__ << "/" << __LINE__  << __FUNCTION__ << "Convert failed";
            hexSplit[i] = "";
            hex = (hexSplit.join(" "));
        }

    }


    return asciiText;

}


void MainWindow::on_asciiEdit_textChanged(const QString &arg1)
{
    if(asciiedit) return;

    asciiedit = true;
    QString updated = arg1;
    QString hex = ASCIITohex(updated);
    ui->hexEdit->setText(hex);

    asciiedit = false;
}

void MainWindow::on_hexEdit_textEdited(const QString &arg1)
{
    if(asciiedit) return;

    asciiedit = true;
    QString updated = arg1;
    QString hex = hexToASCII(updated);
    ui->asciiEdit->setText(hex);

    asciiedit = false;
}

void MainWindow::on_cancelButton_clicked()
{
    cancel = true;
}

QStringList MainWindow::magicNumbersToFile(QByteArray initialbytes)
{
    //https://en.wikipedia.org/wiki/List_of_file_signatures
}

void MainWindow::on_deriveButton_clicked()
{
    static QString originalText = ui->deriveButton->text();

    QHash<QString, QString> keys;
    QHash<QString, QString> IVs;

    Crypto::GenerateKeys(keys, IVs);


    QString bitcheck = ui->aesBitsCombo->currentText().split(" ").first();
    QString aescipher= "aes-" + bitcheck + "-cbc";
    ui->keyEdit->setText(keys[aescipher]);
    ui->ivEdit->setText(IVs[aescipher]);

    ui->bfKeyEdit->setText(keys["bf-cbc"]);
    ui->bfIVEdit->setText(IVs["bf-cbc"]);

    ui->key2FishEdit->setText(keys["twofish"]);
    ui->iv2FishEdit->setText(IVs["twofish"]);

    if(ui->tripleDESVariantCombo->currentText().contains("2")) {

        ui->tripleDESKeyEdit->setText(keys["des-ede-cbc"]);
        ui->tripleDESIVEdit->setText(IVs["des-ede-cbc"]);

    } else {
        ui->tripleDESKeyEdit->setText(keys["des-ede3-cbc"]);
        ui->tripleDESIVEdit->setText(IVs["des-ede3-cbc"]);

    }

    ui->deriveButton->setText(originalText);

}

void MainWindow::on_clearLogButton_clicked()
{
    ui->resultTextEdit->clear();
}

void MainWindow::on_toClipBoardButton_clicked()
{

    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->resultTextEdit->toPlainText());

    statusBar()->showMessage("Copied to clipboard", 3000);

}

void MainWindow::on_hashCalcButton_clicked()
{
    QTemporaryFile temporaryFile("cryptofile-temp");


    if(temporaryFile.open()) {
        QString tempText = ui->directInputHashEdit->toPlainText();
        temporaryFile.write(tempText.toUtf8());
        temporaryFile.close();
    }

    QString filename = temporaryFile.fileName();

    QFile tempFile(filename);
    QDEBUGVAR(filename);

    if(filename.isEmpty()) {
        QDEBUG() << "Filename is blank";
        return;
    }

    if(tempFile.exists()) {

        Crypto crypto;
        crypto.filename = filename;
        crypto.domd2 = true;
        crypto.domd4 = true;
        crypto.doMD5 = true;
        crypto.dosha1 = true;
        crypto.dosha224 = true;
        crypto.dosha256 = true;
        crypto.dosha384 = true;
        crypto.dosha512 = true;
        crypto.doHash();
        ui->resultTextEdit->clear();
        Crc32 crc32;
        quint32 crcresult = crc32.calculateFromFile(filename);
        appendResult("CRC32: " + QString::number(crcresult, 16));
        quint64 chksum = Crypto::Checksum(filename);
        appendResult("Checksum: " + QString::number(chksum, 16).toUpper());
        appendResult(crypto.result);
    }



}

void MainWindow::on_encodeCalcButton_clicked()
{
    QTemporaryFile temporaryIn("cryptofile-temp-in");
    QTemporaryFile temporaryOut("cryptofile-temp-in");


    if(temporaryIn.open()) {
        QString tempText = ui->directInputEncodeEdit->toPlainText();
        temporaryIn.write(tempText.toUtf8());
        temporaryIn.close();
    }

    if(temporaryOut.open()) {
        temporaryIn.close();
    }

    QString fileIn = temporaryIn.fileName();
    QString fileOut = temporaryOut.fileName();

    QFile tempFileIn(fileIn);
    QFile tempFileOut(fileOut);
    QDEBUGVAR(fileIn);

    if(fileIn.isEmpty()) {
        QDEBUG() << "fileIn is blank";
        return;
    }

    if(fileOut.isEmpty()) {
        QDEBUG() << "fileOut is blank";
        return;
    }

    QString preserveText = ui->resultTextEdit->toPlainText();

    ui->resultTextEdit->clear();

    if(tempFileIn.exists()) {
        bool didit = false;
        if(ui->base64DecCheck->isChecked()) {
            didit = true;
            Crypto::Base64Decode(fileIn.toLatin1().data(), fileOut.toLatin1().data());
            if(tempFileOut.open(QFile::ReadOnly)) {
                appendResult(QString(tempFileOut.readAll()));
                tempFileOut.close();
            }
        }
        if(ui->base64EncCheck->isChecked()) {
            didit = true;
            Crypto::Base64Encode(fileIn.toLatin1().data(), fileOut.toLatin1().data());
            if(tempFileOut.open(QFile::ReadOnly)) {
                appendResult(QString(tempFileOut.readAll()));
                tempFileOut.close();
            }
        }
        if(ui->hexCheck->isChecked()) {
            didit = true;
            Crypto::Bin2HEX(fileIn.toLatin1().data(), fileOut.toLatin1().data());
            if(tempFileOut.open(QFile::ReadOnly)) {
                appendResult(QString(tempFileOut.readAll()));
                tempFileOut.close();
            }
        }
        if(ui->binCheck->isChecked()) {
            didit = true;
            Crypto::HEX2Bin(fileIn.toLatin1().data(), fileOut.toLatin1().data());
            if(tempFileOut.open(QFile::ReadOnly)) {
                appendResult(QString(tempFileOut.readAll()));
                tempFileOut.close();
            }
        }

        if(!didit) {
            ui->resultTextEdit->append(preserveText);
            QMessageBox msgBox;
            msgBox.setWindowTitle("No encodings.");
            msgBox.setStandardButtons(QMessageBox::Ok);
            msgBox.setDefaultButton(QMessageBox::Ok);
            msgBox.setIcon(QMessageBox::Warning);
            msgBox.setText("Please check at least 1 encoding.");
            msgBox.exec();

        }

    }


}

QString MainWindow::systemProfile()
{
    QString systemInfo =  "Your system information\n";
    systemInfo +=  QSysInfo::prettyProductName() +  " / " + QSysInfo::kernelType() + " " + QSysInfo::kernelVersion() + "\n";
    systemInfo +=  "Computer name:" + QSysInfo::machineHostName() + "\n";


    systemInfo +=  "CPU arch is " + QSysInfo::currentCpuArchitecture() + " and is ";
    if(QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
        systemInfo +=  "Little Endian\n";
    }
    if(QSysInfo::ByteOrder == QSysInfo::BigEndian) {
        systemInfo +=  "Big Endian\n";
    }

#ifdef __WIN32
    //Extended processor info...
    int CPUInfo[4] = {-1};
    unsigned   nExIds, i =  0;
    char CPUBrandString[0x100];
    // Get the information associated with each extended ID.
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    for (i=0x80000000; i<=nExIds; ++i)
    {
        __cpuid(CPUInfo, i);
        // Interpret CPU brand string
        if  (i == 0x80000002)
            memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
        else if  (i == 0x80000003)
            memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
        else if  (i == 0x80000004)
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
    }
    //string includes manufacturer, model and clockspeed
    systemInfo +=  "CPU Type: " + QString(CPUBrandString) + "\n";

#endif


//SO: http://stackoverflow.com/questions/8122277/getting-memory-information-with-qt
#ifdef __WIN32
    MEMORYSTATUSEX memory_status;
    ZeroMemory(&memory_status, sizeof(MEMORYSTATUSEX));
    memory_status.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memory_status)) {
        if(memory_status.ullTotalPhys > (1024 * 1024 * 1024)) {
            QDEBUGVAR(memory_status.ullTotalPhys);
            systemInfo.append(
                  QString("\nRAM: %1 GiB")
                  .arg(((float) memory_status.ullTotalPhys) / (1024 * 1024 * 1024)));
        } else {
            systemInfo.append(
                  QString("\nRAM: %1 MiB")
                  .arg(((float) memory_status.ullTotalPhys) / (1024 * 1024)));

        }

    } else {
      systemInfo.append("\nUnknown RAM");
    }


#endif

#if __linux__

    if(QFile::exists("/proc/meminfo")) {
        QProcess p;
        p.start("awk", QStringList() << "/MemTotal/ { print $2 }" << "/proc/meminfo");
        p.waitForFinished();
        QString memory = p.readAllStandardOutput();
        systemInfo.append(QString("; RAM: %1 MB").arg(memory.toLong() / 1024));
        p.close();
    }


#endif
#if __APPLE__
    QProcess p;
    p.start("sysctl", QStringList() << "kern.version" << "hw.physmem");
    p.waitForFinished();
    systemInfo += p.readAllStandardOutput();
    p.close();
#endif
    systemInfo.append("\n");

    QFileInfoList drives = QDir::drives();


#ifdef __WIN32
    systemInfo.append("\nMounted drives...\n");
#endif

    QFileInfo drive;
    foreach(drive, drives) {
        QStorageInfo storage(drive.absoluteFilePath());

        if(storage.bytesTotal() < 1) {
            continue;
        }

        systemInfo +=  storage.name() + " " + storage.rootPath() + " (" + QString(storage.fileSystemType()) + ") \n";
        quint64 bytesTotal = storage.bytesTotal()/1000/1000;
        float bytesTotalf = ((float) bytesTotal);
        if(bytesTotal > 1000) {
            systemInfo +=  "Size: " + QString::number(bytesTotalf / 1000) + " GB\n";
        } else {
            systemInfo +=  "Size: " + QString::number(bytesTotalf) + " MB\n";
        }


        bytesTotal = storage.bytesAvailable()/1000/1000;
        bytesTotalf = ((float) bytesTotal);

        if(bytesTotal > 1000) {
            systemInfo +=  "Available: " + QString::number(bytesTotalf / 1000) + " GB\n\n";
        } else {
            systemInfo +=  "Available: " + QString::number(bytesTotalf) + " MB\n\n";
        }

    }



    QList<QNetworkInterface> allInterfaces = QNetworkInterface::allInterfaces();
    QNetworkInterface eth;


    QString startLog = "Your non-loopback addresses: \n";
    QTextStream out (&startLog);

    foreach(eth, allInterfaces) {
        QList<QNetworkAddressEntry> allEntries = eth.addressEntries();
        if(allEntries.size() == 0 || !eth.flags().testFlag(QNetworkInterface::IsUp)) {
            continue;
        }

        QString ethString;
        QTextStream ethOut (&ethString);


        ethOut << "\nFor " << eth.humanReadableName() << " (" << eth.hardwareAddress() <<")" << ":\n";
        QNetworkAddressEntry entry;

        int nonLoopBack = 0;

        foreach (entry, allEntries) {
            if(!entry.ip().isLoopback()) {
                if(entry.ip().toString().contains(":")) {

                    //ignore ipv6 for now
                    //continue;
                }
                nonLoopBack = 1;
                ethOut << entry.ip().toString() << "  /  " << entry.netmask().toString() << "\n";
            }
        }

        if(nonLoopBack) {
            out << ethString;
        }
    }


    systemInfo.append(startLog);

    return systemInfo;

}

int getRandomNumber(const int Min, const int Max)
{
    return ((qrand() % ((Max + 1) - Min)) + Min);
}

void MainWindow::on_genSecurePWButton_clicked()
{
    if(passwordedit) return;

    unsigned int length = ui->secureLengthCombo->currentText().toUInt();
    bool caps = ui->secureCapsCheck->isChecked();
    bool special = ui->secureSpecialCheck->isChecked();
    bool nums = ui->secureNumsCheck->isChecked();
    QString pw; pw.clear();
    QString specials = "!#$%^*_";


    for (unsigned int i=0; i<length; i++) {
        int letter = getRandomNumber(97, 122);
        int specialcharacter = getRandomNumber(0, specials.size() - 1);
        int number = getRandomNumber(0+48, 9+48);
        int choice = getRandomNumber(0, 2);
        int doUpper = getRandomNumber(0, 1);

        char pwChar = (char) letter;
        if(choice == 0) {
            if(caps) {
                if(doUpper == 1) {
                    pwChar = (char) (letter - 32); // send to upper case ASCII
                }
            }
        }

        if(nums && choice == 1) {
            pwChar = (char) number;

        }

        if(special && choice == 2) {
            pwChar = specials.at(specialcharacter).toLatin1();
        }

        pw.append(QChar(pwChar));
    }

    ui->securePWEdit->setText(pw);

}




void MainWindow::on_systemProfileButton_clicked()
{
    SETLOG(systemProfile());
}

void MainWindow::on_copyPWButton_clicked()
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->securePWEdit->text());
    statusBar()->showMessage("Password copied to clipboard", 3000);
}

void MainWindow::on_secureLengthCombo_currentIndexChanged(int index)
{
    Q_UNUSED(index);
    on_genSecurePWButton_clicked();
}

void MainWindow::on_secureCapsCheck_toggled(bool checked)
{
    Q_UNUSED(checked);
    on_genSecurePWButton_clicked();

}

void MainWindow::on_secureSpecialCheck_toggled(bool checked)
{
    Q_UNUSED(checked);
    on_genSecurePWButton_clicked();
}

void MainWindow::on_secureNumsCheck_toggled(bool checked)
{
    Q_UNUSED(checked);
    on_genSecurePWButton_clicked();

}

void MainWindow::on_aesBitsCombo_currentIndexChanged(const QString &arg1)
{
    static QString originalText = ui->deriveButton->text();
    QDEBUGVAR(arg1);
    if(arg1.contains("192") || arg1.contains("256")) {
        if(ui->keyEdit->text().size() < QString("8660569170A6AD92CCB806E50FDB0C242F3B01DEB6F9BCF0E916F96B8FD5F7B1").size()) {
            ui->deriveButton->setText("! " + originalText );

        }
    }

}

void MainWindow::on_tripleDESVariantCombo_currentIndexChanged(const QString &arg1)
{
    static QString originalText = ui->deriveButton->text();
    QDEBUGVAR(arg1);
    if(arg1.contains("3")) {
        if(ui->keyEdit->text().size() < QString("90EB9DE3C7F731C31B08AB9AADFB0BB83F7D8E75F0D46DBA").size()) {
            ui->deriveButton->setText("! " + originalText );

        }
    }

}

void MainWindow::on_deleteFileButton_clicked()
{
    if(QFile::remove(LOGFILE)) {
        statusBar()->showMessage("cryptoknife.log deleted", 3000);
    }

    logbuttondisplay();
}
