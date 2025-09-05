#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    app.setApplicationName("VPN Client");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("VPN Solutions");

    MainWindow window;
    window.show();

    return app.exec();
}
