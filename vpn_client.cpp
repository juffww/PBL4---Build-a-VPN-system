#include "vpn_client.h"
#include <QHostAddress>
#include <QDebug>
#include <QThread>

VPNClient::VPNClient(QObject *parent)
    : QObject(parent), authenticated(false), serverPort(0)
{
    socket = new QTcpSocket(this);
    pingTimer = new QTimer(this);

    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);

    connect(pingTimer, &QTimer::timeout, this, &VPNClient::sendPing);
    pingTimer->setInterval(30000); // 30 seconds
}

VPNClient::~VPNClient()
{
    disconnectFromServer();
}

void VPNClient::connectToServer(const QString& host, int port, const QString& username, const QString& password)
{
    // Kiểm tra nếu đã kết nối thì ngắt trước
    if (socket->state() != QAbstractSocket::UnconnectedState) {
        qDebug() << "Already connected/connecting, disconnecting first...";
        disconnectFromServer();
        // Đợi một chút để đảm bảo disconnect hoàn tất
        QThread::msleep(100);
    }

    serverHost = host;
    serverPort = port;
    authenticated = false;
    assignedVpnIP.clear();

    qDebug() << "Connecting to" << host << ":" << port;

    // Lưu credentials để dùng khi connected
    socket->setProperty("username", username);
    socket->setProperty("password", password);

    // Bắt đầu kết nối socket
    socket->connectToHost(host, port);
}

void VPNClient::onConnected()
{
    qDebug() << "TCP Socket connected to server";

    // Emit signal connected (chỉ thông báo socket đã connect)
    emit connected();

    // Tự động thực hiện authentication
    QString username = socket->property("username").toString();
    QString password = socket->property("password").toString();

    if (!username.isEmpty() && !password.isEmpty()) {
        qDebug() << "Auto-authenticating with username:" << username;
        authenticate(username, password);
    } else {
        emit error("Missing username or password");
    }
}

void VPNClient::disconnectFromServer()
{
    pingTimer->stop();
    authenticated = false;
    assignedVpnIP.clear();

    if (socket->state() != QAbstractSocket::UnconnectedState) {
        sendMessage("DISCONNECT");
        socket->disconnectFromHost();

        if (socket->state() != QAbstractSocket::UnconnectedState) {
            socket->waitForDisconnected(3000);
        }
    }
}

bool VPNClient::isConnected() const
{
    return socket->state() == QAbstractSocket::ConnectedState && authenticated;
}

void VPNClient::requestVPNIP()
{
    if (authenticated) {
        sendMessage("GET_IP");
    }
}

void VPNClient::requestStatus()
{
    if (authenticated) {
        sendMessage("STATUS");
    }
}

//void VPNClient::onConnected()
//{
//    qDebug() << "Connected to server";
//    emit connected();

//    QString username = socket->property("username").toString();
//    QString password = socket->property("password").toString();

//    if (!username.isEmpty() && !password.isEmpty()) {
//        authenticate(username, password);
//    }
//}

void VPNClient::onDisconnected()
{
    qDebug() << "Disconnected from server";
    pingTimer->stop();
    authenticated = false;
    assignedVpnIP.clear();
    emit disconnected();
}

void VPNClient::onReadyRead()
{
    while (socket->canReadLine()) {
        QString message = socket->readLine().trimmed();
        qDebug() << "Received:" << message;

        parseServerMessage(message);
        emit messageReceived(message);
    }
}

void VPNClient::parseServerMessage(const QString& message)
{
    if (message.startsWith("WELCOME|")) {
        qDebug() << "Server welcome message received";
    }
    else if (message.startsWith("AUTH_OK|")) {
        authenticated = true;
        pingTimer->start();

        // Parse VPN IP from AUTH_OK response
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();

            assignedVpnIP = message.mid(start, end - start).trimmed();
            qDebug() << "VPN IP assigned:" << assignedVpnIP;
            emit vpnIPAssigned(assignedVpnIP);
        }

        emit authenticationResult(true, message.mid(8)); // Remove "AUTH_OK|"
    }
    else if (message.startsWith("AUTH_FAIL|")) {
        authenticated = false;
        emit authenticationResult(false, message.mid(10)); // Remove "AUTH_FAIL|"
    }
    else if (message.startsWith("PONG")) {
        qDebug() << "Pong received from server";
    }
    else if (message.startsWith("VPN_IP|")) {
        // Parse VPN IP info: VPN_IP|ip|server_ip
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            assignedVpnIP = parts[1];
            if (parts.size() >= 3) {
                serverIP = parts[2];
            }
            emit vpnIPAssigned(assignedVpnIP);
            qDebug() << "VPN IP updated:" << assignedVpnIP;
        }
    }
    else if (message.startsWith("STATUS|")) {
        // Parse status: STATUS|Connected|VPN_IP:x.x.x.x|Clients:N
        emit statusReceived(message.mid(7)); // Remove "STATUS|"

        // Extract VPN IP from status if available
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();

            QString newVpnIP = message.mid(start, end - start).trimmed();
            if (newVpnIP != assignedVpnIP) {
                assignedVpnIP = newVpnIP;
                emit vpnIPAssigned(assignedVpnIP);
            }
        }
    }
    else if (message.startsWith("ERROR|")) {
        QString errorMsg = message.mid(6); // Remove "ERROR|"
        emit error(errorMsg);
    }
    else if (message.startsWith("BYE|")) {
        qDebug() << "Server goodbye message";
        disconnectFromServer();
    }
}

//void VPNClient::onError(QAbstractSocket::SocketError socketError)
//{
//    Q_UNUSED(socketError)

//    QString errorMsg = QString("Lỗi kết nối: %1").arg(socket->errorString());
//    qDebug() << errorMsg;
//    emit error(errorMsg);
//}

void VPNClient::authenticate(const QString& username, const QString& password)
{
    QString authMessage = QString("AUTH %1 %2").arg(username, password);
    sendMessage(authMessage);
}

void VPNClient::sendMessage(const QString& message)
{
    if (socket->state() == QAbstractSocket::ConnectedState) {
        QString msg = message + "\n";
        socket->write(msg.toUtf8());
        socket->flush();
        qDebug() << "Sent:" << message;
    }
}

void VPNClient::sendPing()
{
    sendMessage("PING");
}

void VPNClient::onError(QAbstractSocket::SocketError socketError)
{
    QString errorMsg;

    switch (socketError) {
        case QAbstractSocket::ConnectionRefusedError:
            errorMsg = "Server từ chối kết nối. Kiểm tra server có đang chạy không.";
            break;
        case QAbstractSocket::RemoteHostClosedError:
            errorMsg = "Server đóng kết nối.";
            break;
        case QAbstractSocket::HostNotFoundError:
            errorMsg = "Không tìm thấy server. Kiểm tra địa chỉ IP.";
            break;
        case QAbstractSocket::SocketTimeoutError:
            errorMsg = "Kết nối timeout.";
            break;
        case QAbstractSocket::NetworkError:
            errorMsg = "Lỗi mạng.";
            break;
        default:
            errorMsg = QString("Lỗi socket: %1").arg(socket->errorString());
            break;
    }

    qDebug() << "Socket Error:" << socketError << "-" << errorMsg;
    qDebug() << "Socket state:" << socket->state();

    emit error(errorMsg);
}
