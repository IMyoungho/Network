#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <iostream>
#include <pcap.h>
#include "parse.h"
using namespace std;

namespace Ui {
class MainWindow;
class parse;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_dev_select_clicked_clicked();
    void on_ap_scanner_clicked_clicked();

private:
    Ui::MainWindow *ui;
    char *interface;
};

#endif // MAINWINDOW_H
