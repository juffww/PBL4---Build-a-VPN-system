#include <QRandomGenerator>
#include <QDateTime>
#include "vpn_client.h"
#include <QHostAddress>
#include <QDebug>
#include <QThread>
#include <cstring>

VPNClient::VPNClient(QObject *parent)
    : QObject(parent), authenticated(false), serverPort(0),
    tunTrafficTimer(nullptr), networkManager(nullptr),
    totalBytesReceived(0), totalBytesSent(0),
    pendingPacketSize(0), isReadingPacketData(false),
    udpReady(false), udpServerPort(0), clientId(0),
    udpHandshakeTimer(nullptr) // <<< SỬA ĐỔI: Khởi tạo là nullptr
{
    socket = new QTcpSocket(this);
    udpSocket = new QUdpSocket(this);

    udpSocket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 65536);
    udpSocket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 65536);

    pingTimer = new QTimer(this);
    networkManager = new QNetworkAccessManager(this);

    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);
    connect(pingTimer, &QTimer::timeout, this, &VPNClient::sendPing);
    connect(udpSocket, &QUdpSocket::readyRead, this, &VPNClient::onUdpReadyRead);

    pingTimer->setInterval(30000);

    tunTrafficTimer = new QTimer(this);
    tunTrafficTimer->setInterval(10);
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
    udpReady = false;  // RESET UDP

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

    // Dừng UDP handshake timer nếu đang chạy
    if (udpHandshakeTimer && udpHandshakeTimer->isActive()) {
        udpHandshakeTimer->stop();
        delete udpHandshakeTimer;
        udpHandshakeTimer = nullptr;
    }

    authenticated = false;
    udpReady = false;

    if (udpSocket->state() == QAbstractSocket::BoundState) {
        udpSocket->close();
    }

    if (tun.isOpened()) {
        tun.close();
    }

    if (socket->state() != QAbstractSocket::UnconnectedState) {
        sendMessage("DISCONNECT");
        socket->disconnectFromHost();
        socket->waitForDisconnected(3000);
    }
}

bool VPNClient::isConnected() const
{
    return socket->state() == QAbstractSocket::ConnectedState && authenticated;
}

void VPNClient::startTUNTrafficGeneration()
{
    if (authenticated && tunTrafficTimer) {
        tunTrafficTimer->start(5);  // Tăng tần suất lên 5ms
    }
}

void VPNClient::stopTUNTrafficGeneration()
{
    if (tunTrafficTimer) tunTrafficTimer->stop();
}

void VPNClient::processTUNTraffic()
{
    if (!authenticated || !tun.isOpened()) return;

    char buffer[2000];
    int packetsRead = 0;

    // Đọc tối đa 20 packets mỗi lần để tránh blocking
    while (packetsRead < 20) {
        int n = tun.readPacket(buffer, sizeof(buffer));
        if (n <= 0) break;

        sendPacketToServer(QByteArray(buffer, n));
        packetsRead++;
    }

    if (packetsRead > 0) {
        emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
    }
}

void VPNClient::sendPacketToServer(const QByteArray& packetData)
{
    if (!authenticated) return;

    if (packetData.size() > 1500) {
        qWarning() << "[PACKET] Packet too large:" << packetData.size();
        return;
    }

    // Ưu tiên UDP nếu sẵn sàng
    if (udpReady && udpSocket->state() == QAbstractSocket::BoundState) {
        // ✅ DÙNG RAW BUFFER
        int totalSize = 8 + packetData.size();
        QByteArray udpPacket(totalSize, 0);

        // Little-endian native
        *(qint32*)udpPacket.data() = clientId;
        *(qint32*)(udpPacket.data() + 4) = packetData.size();
        memcpy(udpPacket.data() + 8, packetData.constData(), packetData.size());

        qint64 sent = udpSocket->writeDatagram(udpPacket, udpServerAddr, udpServerPort);

        if (sent > 0) {
            totalBytesSent += packetData.size();

            static int udpCount = 0;
            if (++udpCount % 100 == 0) {
                qDebug() << "[UDP->SERVER] ✓ Sent" << udpCount << "packets";
            }
            return;
        } else {
            qWarning() << "[UDP] ✗ Send failed:" << udpSocket->errorString();
        }
    }

    // TCP Fallback
    if (socket->state() == QAbstractSocket::ConnectedState) {
        QString header = QString("PACKET_DATA|%1\n").arg(packetData.size());
        socket->write(header.toUtf8());
        qint64 bytesWritten = socket->write(packetData);

        if (bytesWritten > 0) {
            totalBytesSent += bytesWritten;

            static int tcpCount = 0;
            if (++tcpCount % 100 == 0) {
                qDebug() << "[TCP->SERVER] Sent" << tcpCount << "packets (fallback)";
            }
        }
    }
}

// XỬ LÝ UDP PACKETS TỪ SERVER
void VPNClient::onUdpReadyRead()
{
    while (udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(udpSocket->pendingDatagramSize());

        QHostAddress sender;
        quint16 senderPort;
        qint64 size = udpSocket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        if (size < 8) continue;

        // ✅ DÙNG RAW BUFFER - KHÔNG DÙNG QDataStream
        qint32 recvClientId = *(qint32*)datagram.data();
        qint32 packetSize = *(qint32*)(datagram.data() + 4);

        // Xác nhận handshake
        if (recvClientId == clientId && packetSize == 0) {
            if (udpHandshakeTimer && udpHandshakeTimer->isActive()) {
                udpHandshakeTimer->stop();
                delete udpHandshakeTimer;
                udpHandshakeTimer = nullptr;

                udpReady = true;
                qDebug() << "[UDP] ✅ HANDSHAKE COMPLETED - UDP channel is ACTIVE";
            }
            continue;
        }

        // Data packet
        if (recvClientId == clientId && packetSize > 0 && packetSize < 65536) {
            if (datagram.size() >= (8 + packetSize)) {
                QByteArray packet = datagram.mid(8, packetSize);

                int written = tun.writePacket(packet.constData(), packet.size());
                if (written > 0) {
                    totalBytesReceived += written;

                    static int recvCount = 0;
                    if (++recvCount % 50 == 0) {
                        qDebug() << "[UDP->TUN] ✓ Received" << recvCount << "packets";
                    }
                }
            }
        }
    }
}

// Thay thế hàm parseServerMessage() trong vpn_client.cpp:

void VPNClient::parseServerMessage(const QString& message)
{
    if (message.startsWith("AUTH_OK|")) {
        authenticated = true;
        pingTimer->start();

        // 1. Parse CLIENT_ID
        if (message.contains("CLIENT_ID:")) {
            int start = message.indexOf("CLIENT_ID:") + 10;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            clientId = message.mid(start, end - start).toInt();
            qDebug() << "[CONFIG] Client ID:" << clientId;
        }

        // 2. Parse UDP info
        if (message.contains("UDP_PORT:")) {
            int start = message.indexOf("UDP_PORT:") + 9;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            udpServerPort = message.mid(start, end - start).toUShort();
            udpServerAddr = QHostAddress(serverHost);
        }

        // 3. Parse VPN_IP
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            assignedVpnIP = message.mid(start, end - start).trimmed();
            emit vpnIPAssigned(assignedVpnIP);
        }

        // 4. BIND UDP SOCKET TRƯỚC (quan trọng!)
        if (udpSocket->state() != QAbstractSocket::BoundState) {
            if (udpSocket->bind(QHostAddress::AnyIPv4, 0, QAbstractSocket::ShareAddress)) {
                qDebug() << "[UDP] Bound to local port" << udpSocket->localPort();
            } else {
                qWarning() << "[UDP] Failed to bind:" << udpSocket->errorString();
            }
        }

        // 5. GỬI UDP HANDSHAKE TRƯỚC KHI CONFIGURE TUN
        if (udpServerPort > 0 && !udpServerAddr.isNull()) {
            qDebug() << "[UDP] Sending handshake BEFORE TUN configuration...";
            startUdpHandshake();
            QThread::msleep(200); // Đợi handshake hoàn tất
        }

        // 6. SAU ĐÓ MỚI CONFIGURE TUN
        if (tun.create()) {
            if (tun.configure(assignedVpnIP.toStdString(), "255.255.255.0", serverHost.toStdString())) {
                qDebug() << "[TUN] Configured successfully";
                startTUNTrafficGeneration();
            } else {
                qWarning() << "[TUN] Configuration FAILED";
            }
        } else {
            qWarning() << "[TUN] Creation FAILED";
        }

        emit authenticationResult(true, message.mid(8));
    }
    else if (message.startsWith("AUTH_FAIL|")) {
        authenticated = false;
        emit authenticationResult(false, message.mid(10));
    }
    else if (message.startsWith("PACKET_DATA|")) {
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            bool ok;
            int packetSize = parts[1].toInt(&ok);
            if (ok && packetSize > 0 && packetSize < 65536) { // Kiểm tra kích thước hợp lệ
                pendingPacketSize = packetSize;
                isReadingPacketData = true;
                pendingPacketData.clear();
            }
        }
    }
    else if (message.startsWith("STATUS|")) {
        emit statusReceived(message.mid(7));
    }
    else if (message.startsWith("ERROR|")) {
        emit error(message.mid(6));
    }
}

void VPNClient::startUdpHandshake()
{
    qDebug() << "[UDP] Starting handshake sequence...";

    // Tạo timer mới nếu chưa có
    if (udpHandshakeTimer) {
        udpHandshakeTimer->stop();
        delete udpHandshakeTimer;
    }

    udpHandshakeTimer = new QTimer(this);
    udpHandshakeTimer->setSingleShot(false);
    connect(udpHandshakeTimer, &QTimer::timeout, this, &VPNClient::sendUdpHandshake);

    // Gửi handshake ngay lập tức
    sendUdpHandshake();

    // Sau đó gửi lại mỗi 500ms cho đến khi nhận được phản hồi
    udpHandshakeTimer->start(500);
}

void VPNClient::sendUdpHandshake()
{
    if (!udpSocket || udpServerPort == 0 || udpServerAddr.isNull()) {
        qWarning() << "[UDP] Cannot send handshake - invalid parameters";
        return;
    }

    // ✅ DÙNG RAW BUFFER - KHÔNG DÙNG QDataStream
    char handshake[8];
    memset(handshake, 0, 8);

    // Little-endian native
    *(qint32*)handshake = clientId;
    *(qint32*)(handshake + 4) = 0;  // Size = 0 = handshake

    qint64 sent = udpSocket->writeDatagram(handshake, 8, udpServerAddr, udpServerPort);
    if (sent > 0) {
        qDebug() << "[UDP] ✓ Handshake sent: ClientID=" << clientId
                 << "to" << udpServerAddr.toString() << ":" << udpServerPort;
    } else {
        qWarning() << "[UDP] ✗ Handshake send failed:" << udpSocket->errorString();
    }
}

void VPNClient::onReadyRead()
{
    while (socket->bytesAvailable() > 0) {
        if (isReadingPacketData) {
            int remainingBytes = pendingPacketSize - pendingPacketData.size();
            QByteArray chunk = socket->read(remainingBytes);
            pendingPacketData.append(chunk);

            if (pendingPacketData.size() >= pendingPacketSize) {
                writePacketToTUN(pendingPacketData);
                isReadingPacketData = false;
                pendingPacketSize = 0;
                pendingPacketData.clear();
            }
        } else {
            if (socket->canReadLine()) {
                QString message = socket->readLine().trimmed();
                parseServerMessage(message);
                emit messageReceived(message);
            } else {
                break;
            }
        }
    }
}

void VPNClient::writePacketToTUN(const QByteArray& packetData)
{
    if (!tun.isOpened()) return;

    int bytesWritten = tun.writePacket(packetData.constData(), packetData.size());
    if (bytesWritten > 0) {
        totalBytesReceived += bytesWritten;
    }
}

void VPNClient::onDisconnected()
{
    pingTimer->stop();
    stopTUNTrafficGeneration();
    authenticated = false;
    udpReady = false;
    emit disconnected();
}

void VPNClient::onError(QAbstractSocket::SocketError socketError)
{
    QString errorMsg = socket->errorString();
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

void VPNClient::simulateWebBrowsing()
{
    // Giữ nguyên
}

void VPNClient::requestVPNIP()
{
    if (authenticated) sendMessage("GET_IP");
}

void VPNClient::requestStatus()
{
    if (authenticated) sendMessage("STATUS");
}
