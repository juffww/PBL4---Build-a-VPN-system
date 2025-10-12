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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

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
        qDebug() << "[INFO] Starting bidirectional TUN traffic processing";
        tunTrafficTimer->start(10); // Process both directions
    }
}

void VPNClient::stopTUNTrafficGeneration()
{
    if (tunTrafficTimer) {
        qDebug() << "[INFO] Stopping TUN traffic processing";
        tunTrafficTimer->stop();
    }
}

void VPNClient::processTUNTraffic()
{
    if (!authenticated || !tun.isOpened()) return;

    // ĐỌC từ TUN và GỬI lên server (Client → Server → Internet)
    char buffer[2000];
    int n;
    int packetsRead = 0;

    while ((n = tun.readPacket(buffer, sizeof(buffer))) > 0) {
        // Validate và fix packet trước khi gửi
        if (n >= 20) {  // Minimum IPv4 header size
            unsigned char* data = reinterpret_cast<unsigned char*>(buffer);
            unsigned char version = (data[0] >> 4) & 0x0F;

            if (version == 4) {
                // Kiểm tra source IP
                QString srcIP = QString("%1.%2.%3.%4").arg(data[12]).arg(data[13]).arg(data[14]).arg(data[15]);
                QString dstIP = QString("%1.%2.%3.%4").arg(data[16]).arg(data[17]).arg(data[18]).arg(data[19]);
                unsigned char protocol = data[9];

                qDebug() << "[TUN→SERVER] IPv4 packet: From:" << srcIP << "To:" << dstIP
                         << "Protocol:" << protocol << "Size:" << n;

                // Nếu source IP = 0.0.0.0, có thể là lỗi cấu hình
                if (srcIP == "0.0.0.0") {
                    qWarning() << "[WARN] Packet has invalid source IP 0.0.0.0 - This indicates TUN misconfiguration!";
                    qWarning() << "[WARN] Check that VPN IP" << assignedVpnIP << "is properly set on TAP adapter";

                    // Không gửi packet với source IP = 0.0.0.0
                    continue;
                }

                // Chỉ gửi packets có source IP hợp lệ (VPN subnet)
                if (!srcIP.startsWith("10.8.0.")) {
                    qWarning() << "[WARN] Packet source IP" << srcIP << "is not in VPN subnet (10.8.0.0/24)";
                    qWarning() << "[INFO] Expected source IP:" << assignedVpnIP;
                    continue;
                }
            }
        }

        sendPacketToServer(QByteArray(buffer, n));
        packetsRead++;

        // Giới hạn số packet đọc mỗi lần để không block quá lâu
        if (packetsRead >= 10) break;
    }

    // Cập nhật stats
    if (packetsRead > 0 || totalBytesReceived > 0) {
        emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
    }
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
        qDebug() << "[TUN→SERVER] Sent" << bytesWritten << "bytes packet to server";
    } else {
        qWarning() << "[WARN] Failed to send packet to server:" << socket->errorString();
    }
}

void VPNClient::writePacketToTUN(const QByteArray& packetData)
{
    if (!tun.isOpened()) {
        qWarning() << "[WARN] TUN is not opened, cannot write packet";
        return;
    }

    if (packetData.isEmpty()) {
        qWarning() << "[WARN] Attempted to write empty packet to TUN";
        return;
    }

    int bytesWritten = tun.writePacket(packetData.constData(), packetData.size());
    if (bytesWritten > 0) {
        totalBytesReceived += bytesWritten;
        qDebug() << "[SERVER→TUN] Wrote" << bytesWritten << "bytes packet to TUN interface";

        // Debug: Log IP header info for troubleshooting
        if (packetData.size() >= 20) {
            const unsigned char* data = reinterpret_cast<const unsigned char*>(packetData.constData());
            unsigned char version = (data[0] >> 4) & 0x0F;
            unsigned char protocol = data[9];

            QString srcIP = QString("%1.%2.%3.%4").arg(data[12]).arg(data[13]).arg(data[14]).arg(data[15]);
            QString dstIP = QString("%1.%2.%3.%4").arg(data[16]).arg(data[17]).arg(data[18]).arg(data[19]);

            qDebug() << "[PACKET] IPv" << version << "Protocol:" << protocol
                     << "From:" << srcIP << "To:" << dstIP;
        }
    } else if (bytesWritten < 0) {
        qWarning() << "[ERROR] Failed to write packet to TUN (error code:" << bytesWritten << ")";
    } else {
        qWarning() << "[WARN] Wrote 0 bytes to TUN";
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
    qDebug() << "[SOCKET] Has" << socket->bytesAvailable() << "bytes available";

    while (socket->bytesAvailable() > 0) {
        if (isReadingPacketData) {
            // Đang đọc packet data từ server
            int remainingBytes = pendingPacketSize - pendingPacketData.size();
            QByteArray chunk = socket->read(remainingBytes);
            pendingPacketData.append(chunk);

            qDebug() << "[SOCKET] Read" << chunk.size() << "bytes packet data, total:"
                     << pendingPacketData.size() << "/" << pendingPacketSize;

            if (pendingPacketData.size() >= pendingPacketSize) {
                // Đã nhận đủ packet data - GHI XUỐNG TUN
                qDebug() << "[SERVER→TUN] Received complete packet, writing" << pendingPacketSize << "bytes to TUN";
                writePacketToTUN(pendingPacketData);

                // Reset state để đọc control message tiếp
                isReadingPacketData = false;
                pendingPacketSize = 0;
                pendingPacketData.clear();
            }
        } else {
            // Đọc control messages
            if (socket->canReadLine()) {
                QString message = socket->readLine().trimmed();
                qDebug() << "[CONTROL] Received:" << message;
                parseServerMessage(message);
                emit messageReceived(message);
            } else {
                // Không có complete line, chờ thêm data
                break;
            }
        }
    }
}

void VPNClient::parseServerMessage(const QString& message)
{
    if (message.startsWith("WELCOME|")) {
        qDebug() << "[AUTH] Received welcome message";
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

            qDebug() << "[AUTH] Authenticated successfully, VPN IP:" << assignedVpnIP;
            emit vpnIPAssigned(assignedVpnIP);

            // Tạo và cấu hình TUN interface
            if (tun.create()) {
                if (tun.configure(assignedVpnIP.toStdString(), "255.255.255.0", serverHost.toStdString())) {
                    qDebug() << "[TUN] Configured with IP:" << assignedVpnIP;
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
        qDebug() << "[AUTH] Authentication failed";
        emit authenticationResult(false, message.mid(10));
    }
    else if (message.startsWith("PONG")) {
        qDebug() << "[PING] Received PONG from server";
        return;
    }
    else if (message.startsWith("VPN_IP|")) {
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            assignedVpnIP = parts[1];
            if (parts.size() >= 3) serverIP = parts[2];
            qDebug() << "[VPN] IP assigned:" << assignedVpnIP;
            emit vpnIPAssigned(assignedVpnIP);

            if (tun.create()) {
                if (!tun.configure(assignedVpnIP.toStdString(), "255.255.255.0", serverHost.toStdString())) {
                    emit error("Failed to configure TUN interface");
                }
            }
        }
    }
    else if (message.startsWith("PACKET_DATA|")) {
        // Server gửi packet data về (Server → Client → TUN)
        QStringList parts = message.split("|");
        if (parts.size() >= 2) {
            bool ok;
            int packetSize = parts[1].toInt(&ok);
            if (ok && packetSize > 0 && packetSize <= 65535) {
                // Chuẩn bị đọc packet data
                pendingPacketSize = packetSize;
                isReadingPacketData = true;
                pendingPacketData.clear();

                qDebug() << "[PACKET] Expecting packet data of size:" << packetSize;

                // Kiểm tra xem có data ngay lập tức không
                if (socket->bytesAvailable() > 0) {
                    // Đệ quy để xử lý data còn lại
                    QMetaObject::invokeMethod(this, "onReadyRead", Qt::QueuedConnection);
                }
            } else {
                qWarning() << "[ERROR] Invalid packet size:" << packetSize;
            }
        }
    }
    else if (message.startsWith("PACKET|")) {
        // Backward compatibility với old protocol
        QString packetData = message.mid(7);
        totalBytesReceived += packetData.length();
        qDebug() << "[PACKET] Received old-style packet:" << packetData.length() << "bytes";
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
        qWarning() << "[ERROR]" << message.mid(6);
        emit error(message.mid(6));
    }
    else if (message.startsWith("BYE|")) {
        qDebug() << "[DISCONNECT] Server sent BYE";
        disconnectFromServer();
    }
    else {
        qDebug() << "[UNKNOWN] Message:" << message;
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
    qWarning() << "[SOCKET ERROR]" << errorMsg;
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
        qDebug() << "[SEND]" << message;
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

// #include <QRandomGenerator>
// #include <QDateTime>
// #include "vpn_client.h"
// #include <QHostAddress>
// #include <QDebug>
// #include <QThread>
// #include <QTimer>
// #include <QNetworkAccessManager>
// #include <QNetworkRequest>
// #include <QNetworkReply>
// #include <QUrl>

// #ifdef _WIN32
// #include <winsock2.h>
// #include <ws2tcpip.h>
// #endif

// VPNClient::VPNClient(QObject *parent)
//     : QObject(parent), authenticated(false), serverPort(0),
//     tunTrafficTimer(nullptr), networkManager(nullptr),
//     totalBytesReceived(0), totalBytesSent(0),
//     pendingPacketSize(0), isReadingPacketData(false)
// {
//     socket = new QTcpSocket(this);
//     pingTimer = new QTimer(this);
//     networkManager = new QNetworkAccessManager(this);

//     connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
//     connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
//     connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
//     connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);
//     connect(pingTimer, &QTimer::timeout, this, &VPNClient::sendPing);

//     pingTimer->setInterval(30000);

//     tunTrafficTimer = new QTimer(this);
//     connect(tunTrafficTimer, &QTimer::timeout, this, &VPNClient::processTUNTraffic);
// }

// VPNClient::~VPNClient()
// {
//     disconnectFromServer();
// }

// void VPNClient::connectToServer(const QString& host, int port, const QString& username, const QString& password)
// {
//     if (socket->state() != QAbstractSocket::UnconnectedState) {
//         socket->disconnectFromHost();
//         QThread::msleep(100);
//     }

//     serverHost = host;
//     serverPort = port;
//     authenticated = false;
//     assignedVpnIP.clear();
//     totalBytesReceived = 0;
//     totalBytesSent = 0;
//     pendingPacketSize = 0;
//     isReadingPacketData = false;
//     pendingPacketData.clear();

//     socket->setProperty("username", username);
//     socket->setProperty("password", password);
//     socket->connectToHost(host, port);
// }

// void VPNClient::onConnected()
// {
//     QString username = socket->property("username").toString();
//     QString password = socket->property("password").toString();
//     emit connected();

//     if (!username.isEmpty() && !password.isEmpty()) {
//         authenticate(username, password);
//     } else {
//         emit error("Missing username or password");
//     }
// }

// void VPNClient::disconnectFromServer()
// {
//     pingTimer->stop();
//     if (tunTrafficTimer) tunTrafficTimer->stop();

//     authenticated = false;
//     assignedVpnIP.clear();
//     pendingPacketSize = 0;
//     isReadingPacketData = false;
//     pendingPacketData.clear();

//     if (tun.isOpened()) {
//         tun.close();
//     }

//     if (socket->state() != QAbstractSocket::UnconnectedState) {
//         sendMessage("DISCONNECT");
//         socket->disconnectFromHost();
//         if (socket->state() != QAbstractSocket::UnconnectedState) {
//             socket->waitForDisconnected(3000);
//         }
//     }
// }

// bool VPNClient::isConnected() const
// {
//     return socket->state() == QAbstractSocket::ConnectedState && authenticated;
// }

// void VPNClient::startTUNTrafficGeneration()
// {
//     if (authenticated && tunTrafficTimer) {
//         qDebug() << "[INFO] Starting bidirectional TUN traffic processing";
//         tunTrafficTimer->start(10); // Process both directions
//     }
// }

// void VPNClient::stopTUNTrafficGeneration()
// {
//     if (tunTrafficTimer) {
//         qDebug() << "[INFO] Stopping TUN traffic processing";
//         tunTrafficTimer->stop();
//     }
// }

// void VPNClient::processTUNTraffic()
// {
//     if (!authenticated || !tun.isOpened()) return;

//     // ĐỌC từ TUN và GỬI lên server (Client → Server → Internet)
//     char buffer[2000];
//     int n;
//     int packetsRead = 0;

//     while ((n = tun.readPacket(buffer, sizeof(buffer))) > 0) {
//         sendPacketToServer(QByteArray(buffer, n));
//         packetsRead++;

//         // Giới hạn số packet đọc mỗi lần để không block quá lâu
//         if (packetsRead >= 10) break;
//     }

//     // Cập nhật stats
//     if (packetsRead > 0 || totalBytesReceived > 0) {
//         emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
//     }
// }

// void VPNClient::sendPacketToServer(const QByteArray& packetData)
// {
//     if (!authenticated || socket->state() != QAbstractSocket::ConnectedState) {
//         return;
//     }

//     // Gửi packet với protocol header
//     QString header = QString("PACKET_DATA|%1\n").arg(packetData.size());
//     socket->write(header.toUtf8());
//     int bytesWritten = socket->write(packetData);

//     if (bytesWritten > 0) {
//         totalBytesSent += bytesWritten;
//         qDebug() << "[TUN→SERVER] Sent" << bytesWritten << "bytes packet to server";
//     } else {
//         qWarning() << "[WARN] Failed to send packet to server:" << socket->errorString();
//     }
// }

// void VPNClient::writePacketToTUN(const QByteArray& packetData)
// {
//     if (!tun.isOpened()) {
//         qWarning() << "[WARN] TUN is not opened, cannot write packet";
//         return;
//     }

//     if (packetData.isEmpty()) {
//         qWarning() << "[WARN] Attempted to write empty packet to TUN";
//         return;
//     }

//     int bytesWritten = tun.writePacket(packetData.constData(), packetData.size());
//     if (bytesWritten > 0) {
//         totalBytesReceived += bytesWritten;
//         qDebug() << "[SERVER→TUN] Wrote" << bytesWritten << "bytes packet to TUN interface";

//         // Debug: Log IP header info for troubleshooting
//         if (packetData.size() >= 20) {
//             const unsigned char* data = reinterpret_cast<const unsigned char*>(packetData.constData());
//             unsigned char version = (data[0] >> 4) & 0x0F;
//             unsigned char protocol = data[9];

//             QString srcIP = QString("%1.%2.%3.%4").arg(data[12]).arg(data[13]).arg(data[14]).arg(data[15]);
//             QString dstIP = QString("%1.%2.%3.%4").arg(data[16]).arg(data[17]).arg(data[18]).arg(data[19]);

//             qDebug() << "[PACKET] IPv" << version << "Protocol:" << protocol
//                      << "From:" << srcIP << "To:" << dstIP;
//         }
//     } else if (bytesWritten < 0) {
//         qWarning() << "[ERROR] Failed to write packet to TUN (error code:" << bytesWritten << ")";
//     } else {
//         qWarning() << "[WARN] Wrote 0 bytes to TUN";
//     }
// }

// void VPNClient::simulateWebBrowsing()
// {
//     if (!authenticated) return;

//     QStringList urls = {"http://httpbin.org/get", "http://httpbin.org/json", "http://httpbin.org/html"};
//     QString randomUrl = urls[QRandomGenerator::global()->bounded(urls.size())];
//     QString httpRequest = QString("GET %1 HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: VPN-Client\r\n\r\n").arg(randomUrl);

//     // Tạo fake HTTP packet
//     QByteArray fakePacket = httpRequest.toUtf8();
//     sendPacketToServer(fakePacket);

//     // Simulate response after 1 second
//     QTimer::singleShot(1000, this, [this](){
//         int responseSize = 2048 + (QRandomGenerator::global()->bounded(4096));
//         totalBytesReceived += responseSize;
//         emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
//     });
// }

// void VPNClient::requestVPNIP()
// {
//     if (authenticated) sendMessage("GET_IP");
// }

// void VPNClient::requestStatus()
// {
//     if (authenticated) sendMessage("STATUS");
// }

// void VPNClient::onDisconnected()
// {
//     pingTimer->stop();
//     stopTUNTrafficGeneration();
//     authenticated = false;
//     assignedVpnIP.clear();
//     pendingPacketSize = 0;
//     isReadingPacketData = false;
//     pendingPacketData.clear();
//     emit disconnected();
// }

// void VPNClient::onReadyRead()
// {
//     qDebug() << "[SOCKET] Has" << socket->bytesAvailable() << "bytes available";

//     while (socket->bytesAvailable() > 0) {
//         if (isReadingPacketData) {
//             // Đang đọc packet data từ server
//             int remainingBytes = pendingPacketSize - pendingPacketData.size();
//             QByteArray chunk = socket->read(remainingBytes);
//             pendingPacketData.append(chunk);

//             qDebug() << "[SOCKET] Read" << chunk.size() << "bytes packet data, total:"
//                      << pendingPacketData.size() << "/" << pendingPacketSize;

//             if (pendingPacketData.size() >= pendingPacketSize) {
//                 // Đã nhận đủ packet data - GHI XUỐNG TUN
//                 qDebug() << "[SERVER→TUN] Received complete packet, writing" << pendingPacketSize << "bytes to TUN";
//                 writePacketToTUN(pendingPacketData);

//                 // Reset state để đọc control message tiếp
//                 isReadingPacketData = false;
//                 pendingPacketSize = 0;
//                 pendingPacketData.clear();
//             }
//         } else {
//             // Đọc control messages
//             if (socket->canReadLine()) {
//                 QString message = socket->readLine().trimmed();
//                 qDebug() << "[CONTROL] Received:" << message;
//                 parseServerMessage(message);
//                 emit messageReceived(message);
//             } else {
//                 // Không có complete line, chờ thêm data
//                 break;
//             }
//         }
//     }
// }

// void VPNClient::parseServerMessage(const QString& message)
// {
//     if (message.startsWith("WELCOME|")) {
//         qDebug() << "[AUTH] Received welcome message";
//         return;
//     }
//     else if (message.startsWith("AUTH_OK|")) {
//         authenticated = true;
//         pingTimer->start();

//         if (message.contains("VPN_IP:")) {
//             int start = message.indexOf("VPN_IP:") + 7;
//             int end = message.indexOf("|", start);
//             if (end == -1) end = message.length();
//             assignedVpnIP = message.mid(start, end - start).trimmed();

//             qDebug() << "[AUTH] Authenticated successfully, VPN IP:" << assignedVpnIP;
//             emit vpnIPAssigned(assignedVpnIP);

//             // Tạo và cấu hình TUN interface
//             if (tun.create()) {
//                 if (tun.configure(assignedVpnIP.toStdString(), "255.255.255.0", serverHost.toStdString())) {
//                     qDebug() << "[TUN] Configured with IP:" << assignedVpnIP;
//                     startTUNTrafficGeneration();
//                 } else {
//                     emit error("Failed to configure TUN interface");
//                 }
//             } else {
//                 emit error("Failed to create TUN interface");
//             }
//         }
//         emit authenticationResult(true, message.mid(8));
//     }
//     else if (message.startsWith("AUTH_FAIL|")) {
//         authenticated = false;
//         qDebug() << "[AUTH] Authentication failed";
//         emit authenticationResult(false, message.mid(10));
//     }
//     else if (message.startsWith("PONG")) {
//         qDebug() << "[PING] Received PONG from server";
//         return;
//     }
//     else if (message.startsWith("VPN_IP|")) {
//         QStringList parts = message.split("|");
//         if (parts.size() >= 2) {
//             assignedVpnIP = parts[1];
//             if (parts.size() >= 3) serverIP = parts[2];
//             qDebug() << "[VPN] IP assigned:" << assignedVpnIP;
//             emit vpnIPAssigned(assignedVpnIP);

//             if (tun.create()) {
//                 if (!tun.configure(assignedVpnIP.toStdString(), "255.255.255.0", serverHost.toStdString())) {
//                     emit error("Failed to configure TUN interface");
//                 }
//             }
//         }
//     }
//     else if (message.startsWith("PACKET_DATA|")) {
//         // Server gửi packet data về (Server → Client → TUN)
//         QStringList parts = message.split("|");
//         if (parts.size() >= 2) {
//             bool ok;
//             int packetSize = parts[1].toInt(&ok);
//             if (ok && packetSize > 0 && packetSize <= 65535) {
//                 // Chuẩn bị đọc packet data
//                 pendingPacketSize = packetSize;
//                 isReadingPacketData = true;
//                 pendingPacketData.clear();

//                 qDebug() << "[PACKET] Expecting packet data of size:" << packetSize;

//                 // Kiểm tra xem có data ngay lập tức không
//                 if (socket->bytesAvailable() > 0) {
//                     // Đệ quy để xử lý data còn lại
//                     QMetaObject::invokeMethod(this, "onReadyRead", Qt::QueuedConnection);
//                 }
//             } else {
//                 qWarning() << "[ERROR] Invalid packet size:" << packetSize;
//             }
//         }
//     }
//     else if (message.startsWith("PACKET|")) {
//         // Backward compatibility với old protocol
//         QString packetData = message.mid(7);
//         totalBytesReceived += packetData.length();
//         qDebug() << "[PACKET] Received old-style packet:" << packetData.length() << "bytes";
//         emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
//     }
//     else if (message.startsWith("STATUS|")) {
//         emit statusReceived(message.mid(7));
//         if (message.contains("VPN_IP:")) {
//             int start = message.indexOf("VPN_IP:") + 7;
//             int end = message.indexOf("|", start);
//             if (end == -1) end = message.length();
//             QString newVpnIP = message.mid(start, end - start).trimmed();
//             if (newVpnIP != assignedVpnIP) {
//                 assignedVpnIP = newVpnIP;
//                 emit vpnIPAssigned(assignedVpnIP);
//             }
//         }
//     }
//     else if (message.startsWith("ERROR|")) {
//         qWarning() << "[ERROR]" << message.mid(6);
//         emit error(message.mid(6));
//     }
//     else if (message.startsWith("BYE|")) {
//         qDebug() << "[DISCONNECT] Server sent BYE";
//         disconnectFromServer();
//     }
//     else {
//         qDebug() << "[UNKNOWN] Message:" << message;
//     }
// }

// void VPNClient::onError(QAbstractSocket::SocketError socketError)
// {
//     QString errorMsg;
//     switch (socketError) {
//     case QAbstractSocket::ConnectionRefusedError:
//         errorMsg = "Server từ chối kết nối. Kiểm tra server có đang chạy không.";
//         break;
//     case QAbstractSocket::RemoteHostClosedError:
//         errorMsg = "Server đóng kết nối.";
//         break;
//     case QAbstractSocket::HostNotFoundError:
//         errorMsg = "Không tìm thấy server. Kiểm tra địa chỉ IP.";
//         break;
//     case QAbstractSocket::SocketTimeoutError:
//         errorMsg = "Kết nối timeout.";
//         break;
//     case QAbstractSocket::NetworkError:
//         errorMsg = "Lỗi mạng.";
//         break;
//     default:
//         errorMsg = QString("Lỗi socket: %1").arg(socket->errorString());
//         break;
//     }
//     qWarning() << "[SOCKET ERROR]" << errorMsg;
//     emit error(errorMsg);
// }

// void VPNClient::authenticate(const QString& username, const QString& password)
// {
//     sendMessage(QString("AUTH %1 %2").arg(username, password));
// }

// void VPNClient::sendMessage(const QString& message)
// {
//     if (socket->state() == QAbstractSocket::ConnectedState) {
//         socket->write((message + "\n").toUtf8());
//         socket->flush();
//         qDebug() << "[SEND]" << message;
//     }
// }

// void VPNClient::sendPing()
// {
//     sendMessage("PING");
// }

// quint64 VPNClient::getBytesReceived() const
// {
//     return totalBytesReceived;
// }

// quint64 VPNClient::getBytesSent() const
// {
//     return totalBytesSent;
// }
