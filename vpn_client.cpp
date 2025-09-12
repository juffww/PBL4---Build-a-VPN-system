#include <QRandomGenerator>
#include <QDateTime>
#include "vpn_client.h"
#include <QHostAddress>
#include <QDebug>
#include <QThread>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>

VPNClient::VPNClient(QObject *parent)
    : QObject(parent), authenticated(false), serverPort(0),
      tunTrafficTimer(nullptr), networkManager(nullptr),
      totalBytesReceived(0), totalBytesSent(0)
{
    socket = new QTcpSocket(this);
    pingTimer = new QTimer(this);
    networkManager = new QNetworkAccessManager(this);
    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);
    connect(pingTimer, &QTimer::timeout, this, &VPNClient::sendPing);
    pingTimer->setInterval(30000);
    tunTrafficTimer = new QTimer(this);
    connect(tunTrafficTimer, &QTimer::timeout, this, &VPNClient::generateTUNTraffic);
}

VPNClient::~VPNClient()
{
    disconnectFromServer();
}

void VPNClient::connectToServer(const QString& host, int port, const QString& username, const QString& password)
{
    if (socket->state() != QAbstractSocket::UnconnectedState) {
        disconnectFromServer();
        QThread::msleep(100);
    }
    serverHost = host;
    serverPort = port;
    authenticated = false;
    assignedVpnIP.clear();
    totalBytesReceived = 0;
    totalBytesSent = 0;
    socket->setProperty("username", username);
    socket->setProperty("password", password);
    socket->connectToHost(host, port);
}

void VPNClient::onConnected()
{
    QString username = socket->property("username").toString();
    QString password = socket->property("password").toString();
    emit connected();
    if (!username.isEmpty() && !password.isEmpty()) {
        authenticate(username, password);
    } else {
        emit error("Missing username or password");
    }
}

void VPNClient::disconnectFromServer()
{
    pingTimer->stop();
    if (tunTrafficTimer) tunTrafficTimer->stop();
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

void VPNClient::startTUNTrafficGeneration()
{
    if (authenticated && tunTrafficTimer) tunTrafficTimer->start(2000);
}

void VPNClient::stopTUNTrafficGeneration()
{
    if (tunTrafficTimer) tunTrafficTimer->stop();
}

void VPNClient::generateTUNTraffic()
{
    if (!authenticated || assignedVpnIP.isEmpty()) return;
    static int packetCounter = 0;
    packetCounter++;
    QString fakePacket = QString("FAKE_PING_%1|%2|8.8.8.8|%3")
                        .arg(packetCounter)
                        .arg(assignedVpnIP)
                        .arg(QDateTime::currentMSecsSinceEpoch());
    QString packetMessage = QString("PACKET|%1").arg(fakePacket);
    sendMessage(packetMessage);
    totalBytesSent += fakePacket.length();
    if (packetCounter % 3 == 0) {
        totalBytesReceived += 1024 + (QRandomGenerator::global()->bounded(2048));
    }
    emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
}

void VPNClient::simulateWebBrowsing()
{
    if (!authenticated) return;
    QStringList urls = {"http://httpbin.org/get","http://httpbin.org/json","http://httpbin.org/html"};
    QString randomUrl = urls[QRandomGenerator::global()->bounded(urls.size())];
    QString httpRequest = QString("GET %1 HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: VPN-Client\r\n\r\n").arg(randomUrl);
    QString packetMessage = QString("PACKET|HTTP_REQ|%1|%2").arg(assignedVpnIP).arg(httpRequest);
    sendMessage(packetMessage);
    totalBytesSent += httpRequest.length();
    QTimer::singleShot(1000, this, [this](){
        totalBytesReceived += 2048 + (QRandomGenerator::global()->bounded(4096));
        emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
    });
}

void VPNClient::requestVPNIP()
{
    if (authenticated) sendMessage("GET_IP");
}

void VPNClient::requestStatus()
{
    if (authenticated) sendMessage("STATUS");
}

void VPNClient::onDisconnected()
{
    pingTimer->stop();
    stopTUNTrafficGeneration();
    authenticated = false;
    assignedVpnIP.clear();
    emit disconnected();
}

void VPNClient::onReadyRead()
{
    while (socket->canReadLine()) {
        QString message = socket->readLine().trimmed();
        parseServerMessage(message);
        emit messageReceived(message);
    }
}

void VPNClient::parseServerMessage(const QString& message)
{
    if (message.startsWith("WELCOME|")) return;
    else if (message.startsWith("AUTH_OK|")) {
        authenticated = true;
        pingTimer->start();
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            assignedVpnIP = message.mid(start, end - start).trimmed();
            emit vpnIPAssigned(assignedVpnIP);
            startTUNTrafficGeneration();
        }
        emit authenticationResult(true, message.mid(8));
    }
    else if (message.startsWith("AUTH_FAIL|")) {
        authenticated = false;
        emit authenticationResult(false, message.mid(10));
    }
    else if (message.startsWith("PONG")) return;
    else if (message.startsWith("VPN_IP|")) {
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            assignedVpnIP = parts[1];
            if (parts.size() >= 3) serverIP = parts[2];
            emit vpnIPAssigned(assignedVpnIP);
        }
    }
    else if (message.startsWith("PACKET|")) {
        QString packetData = message.mid(7);
        totalBytesReceived += packetData.length();
        emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
    }
    else if (message.startsWith("STATUS|")) {
        emit statusReceived(message.mid(7));
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
    else if (message.startsWith("ERROR|")) emit error(message.mid(6));
    else if (message.startsWith("BYE|")) disconnectFromServer();
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
    emit error(errorMsg);
}

void VPNClient::authenticate(const QString& username, const QString& password)
{
    sendMessage(QString("AUTH %1 %2").arg(username, password));
}

void VPNClient::sendMessage(const QString& message)
{
    if (socket->state() == QAbstractSocket::ConnectedState) {
        socket->write((message + "\n").toUtf8());
        socket->flush();
    }
}

void VPNClient::sendPing()
{
    sendMessage("PING");
}

quint64 VPNClient::getBytesReceived() const
{
    return totalBytesReceived;
}

quint64 VPNClient::getBytesSent() const
{
    return totalBytesSent;
}
