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
    totalBytesReceived(0), totalBytesSent(0),
    pendingPacketSize(0), isReadingPacketData(false)
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
    connect(tunTrafficTimer, &QTimer::timeout, this, &VPNClient::processTUNTraffic);
}

VPNClient::~VPNClient()
{
    disconnectFromServer();
}

void VPNClient::connectToServer(const QString& host, int port, const QString& username, const QString& password)
{
    if (socket->state() != QAbstractSocket::UnconnectedState) {
        socket->disconnectFromHost();
        QThread::msleep(100);
    }

    serverHost = host;
    serverPort = port;
    authenticated = false;
    assignedVpnIP.clear();
    totalBytesReceived = 0;
    totalBytesSent = 0;
    pendingPacketSize = 0;
    isReadingPacketData = false;
    pendingPacketData.clear();

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
    pendingPacketSize = 0;
    isReadingPacketData = false;
    pendingPacketData.clear();

    if (tun.isOpened()) {
        tun.close();
    }

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
    if (authenticated && tunTrafficTimer) {
        tunTrafficTimer->start(10); // Tăng tần số để responsive hơn
    }
}

void VPNClient::stopTUNTrafficGeneration()
{
    if (tunTrafficTimer) tunTrafficTimer->stop();
}

void VPNClient::processTUNTraffic()
{
    if (!authenticated || !tun.isOpened()) return;

    // CHỈ đọc từ TUN và gửi lên server
    char buffer[2000];
    int n;
    while ((n = tun.readPacket(buffer, sizeof(buffer))) > 0) {
        sendPacketToServer(QByteArray(buffer, n));
    }

    emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
}

void VPNClient::sendPacketToServer(const QByteArray& packetData)
{
    if (!authenticated || socket->state() != QAbstractSocket::ConnectedState) {
        return;
    }

    // Gửi packet với protocol header
    QString header = QString("PACKET_DATA|%1\n").arg(packetData.size());
    socket->write(header.toUtf8());
    int bytesWritten = socket->write(packetData);

    if (bytesWritten > 0) {
        totalBytesSent += bytesWritten;
        qDebug() << "[DEBUG] Sent" << bytesWritten << "bytes packet to server";
    } else {
        qWarning() << "[WARN] Failed to send packet to server:" << socket->errorString();
    }
}

void VPNClient::writePacketToTUN(const QByteArray& packetData)
{
    if (!tun.isOpened()) return;

    int bytesWritten = tun.writePacket(packetData.constData(), packetData.size());
    if (bytesWritten > 0) {
        totalBytesReceived += bytesWritten;
        qDebug() << "[DEBUG] Wrote" << bytesWritten << "bytes packet to TUN";
    } else {
        qWarning() << "[WARN] Failed to write packet to TUN";
    }
}

void VPNClient::simulateWebBrowsing()
{
    if (!authenticated) return;

    QStringList urls = {"http://httpbin.org/get", "http://httpbin.org/json", "http://httpbin.org/html"};
    QString randomUrl = urls[QRandomGenerator::global()->bounded(urls.size())];
    QString httpRequest = QString("GET %1 HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: VPN-Client\r\n\r\n").arg(randomUrl);

    // Tạo fake HTTP packet
    QByteArray fakePacket = httpRequest.toUtf8();
    sendPacketToServer(fakePacket);

    // Simulate response after 1 second
    QTimer::singleShot(1000, this, [this](){
        int responseSize = 2048 + (QRandomGenerator::global()->bounded(4096));
        totalBytesReceived += responseSize;
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
    pendingPacketSize = 0;
    isReadingPacketData = false;
    pendingPacketData.clear();
    emit disconnected();
}

void VPNClient::onReadyRead()
{
    qDebug() << "[DEBUG] Socket has" << socket->bytesAvailable() << "bytes available";

    while (socket->bytesAvailable() > 0) {
        if (isReadingPacketData) {
            // Đang đọc packet data
            int remainingBytes = pendingPacketSize - pendingPacketData.size();
            QByteArray chunk = socket->read(remainingBytes);
            pendingPacketData.append(chunk);

            qDebug() << "[DEBUG] Read" << chunk.size() << "bytes packet data, total:"
                     << pendingPacketData.size() << "/" << pendingPacketSize;

            if (pendingPacketData.size() >= pendingPacketSize) {
                // Đã nhận đủ packet data
                qDebug() << "[CLIENT->TUN] Writing" << pendingPacketSize << "bytes to TUN";
                writePacketToTUN(pendingPacketData);

                // Reset state
                isReadingPacketData = false;
                pendingPacketSize = 0;
                pendingPacketData.clear();
            }
        } else {
            // Đọc control messages
            if (socket->canReadLine()) {
                QString message = socket->readLine().trimmed();
                qDebug() << "[DEBUG] Received control message:" << message;
                parseServerMessage(message);
                emit messageReceived(message);
            } else {
                // Không có complete line, đợi thêm data
                break;
            }
        }
    }
}

void VPNClient::parseServerMessage(const QString& message)
{
    qDebug() << "[DEBUG] Received message:" << message;

    if (message.startsWith("WELCOME|")) {
        return;
    }
    else if (message.startsWith("AUTH_OK|")) {
        authenticated = true;
        pingTimer->start();

        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            assignedVpnIP = message.mid(start, end - start).trimmed();
            emit vpnIPAssigned(assignedVpnIP);

            // Tạo và cấu hình TUN interface
            if (tun.create()) {
                if (tun.configure(assignedVpnIP.toStdString(), "24", "10.8.0.1")) {
                    qDebug() << "[DEBUG] TUN configured with IP:" << assignedVpnIP;
                    startTUNTrafficGeneration();
                } else {
                    emit error("Failed to configure TUN interface");
                }
            } else {
                emit error("Failed to create TUN interface");
            }
        }
        emit authenticationResult(true, message.mid(8));
    }
    else if (message.startsWith("AUTH_FAIL|")) {
        authenticated = false;
        emit authenticationResult(false, message.mid(10));
    }
    else if (message.startsWith("PONG")) {
        qDebug() << "[DEBUG] Received PONG from server";
        return;
    }
    else if (message.startsWith("VPN_IP|")) {
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            assignedVpnIP = parts[1];
            if (parts.size() >= 3) serverIP = parts[2];
            emit vpnIPAssigned(assignedVpnIP);

            if (tun.create()) {
                if (!tun.configure(assignedVpnIP.toStdString(), "24", "10.8.0.1")) {
                    emit error("Failed to configure TUN interface");
                }
            }
        }
    }
    else if (message.startsWith("PACKET_DATA|")) {
        // Server gửi packet data về
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            bool ok;
            int packetSize = parts[1].toInt(&ok);
            if (ok && packetSize > 0) {
                // Chuẩn bị đọc packet data
                pendingPacketSize = packetSize;
                isReadingPacketData = true;
                pendingPacketData.clear();

                qDebug() << "[DEBUG] Expecting packet data of size:" << packetSize;

                // Kiểm tra xem có data ngay lập tức không
                if (socket->bytesAvailable() > 0) {
                    onReadyRead(); // Process remaining data
                }
            }
        }
    }
    else if (message.startsWith("PACKET|")) {
        // Backward compatibility với old protocol
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
    else if (message.startsWith("ERROR|")) {
        emit error(message.mid(6));
    }
    else if (message.startsWith("BYE|")) {
        disconnectFromServer();
    }
    else {
        qDebug() << "[DEBUG] Unknown message:" << message;
    }
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
        qDebug() << "[DEBUG] Sent message:" << message;
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
