#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStringList>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void processSettings(bool save);
public slots:
    void poodlepic();
protected:
    void dragEnterEvent(QDragEnterEvent* event);
    void dragMoveEvent(QDragMoveEvent* event);
    void dragLeaveEvent(QDragLeaveEvent* event);
    void dropEvent(QDropEvent* event);


    virtual bool openFiles(const QStringList& pathList);

private slots:
    void on_epochEdit_textEdited(const QString &arg1);


    void on_dateTimeEdit_dateTimeChanged(const QDateTime &dateTime);


    void on_asciiEdit_textChanged(const QString &arg1);

    void on_hexEdit_textEdited(const QString &arg1);


    void on_cancelButton_clicked();


    void on_deriveButton_clicked();

    void on_clearLogButton_clicked();

    void on_toClipBoardButton_clicked();

    void on_hashCalcButton_clicked();

    void on_encodeCalcButton_clicked();

    QString systemProfile();

    void on_systemProfileButton_clicked();

    void on_genSecurePWButton_clicked();

    void on_copyPWButton_clicked();

    void on_secureLengthCombo_currentIndexChanged(int index);

    void on_secureCapsCheck_toggled(bool checked);

    void on_secureSpecialCheck_toggled(bool checked);

    void on_secureNumsCheck_toggled(bool checked);



    void on_aesBitsCombo_currentIndexChanged(const QString &arg1);

    void on_tripleDESVariantCombo_currentIndexChanged(const QString &arg1);

    void on_deleteFileButton_clicked();

private:
    Ui::MainWindow *ui;
    QString doCrypto(QString filename);
    void appendResult(QString result);
    bool epochedit;
    bool asciiedit;

    bool passwordedit;
    bool directHash;

    void launchBrowser();

    void generateUrlButton(QString name, QString link);

    bool cancel;
    QStringList magicNumbersToFile(QByteArray initialbytes);
    void logbuttondisplay();
};

#endif // MAINWINDOW_H
