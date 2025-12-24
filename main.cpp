#include <QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    //argc: Số lượng đối số dòng lệnh (argument count), bao gồm tên chương trình. Ví dụ: Nếu chạy ./program -option, argc = 2.
    //argv[]: Mảng con trỏ char chứa các đối số (argument vector). argv[0] luôn là tên chương trình.
    QApplication app(argc, argv);

    app.setApplicationName("VPN Client");
    app.setApplicationVersion("1.0");
    app.setOrganizationName("VPN Solutions");

    MainWindow window;
    window.show();

    return app.exec();
}
