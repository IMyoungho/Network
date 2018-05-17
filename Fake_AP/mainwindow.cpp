#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}
MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_dev_select_clicked_clicked()
{
    QString a = ui->dev_select->text();
    QByteArray ba=a.toLatin1();
    this->interface = ba.data();
    ui->dev_select_clicked->setDisabled(true);
    ui->show_scan_ap->append("** Current interface : " + a);
}
void MainWindow::on_ap_scanner_clicked_clicked()
{

}
