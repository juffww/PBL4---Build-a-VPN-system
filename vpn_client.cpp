#include <QRandomGenerator>
#include <QDateTime>
#include "vpn_client.h"
// #include "crypto_client.h"
#include <QHostAddress>
#include <QDebug>
#include <QThread>
#include <cstring>
#include <QRegularExpression>
#include <iostream>
#include <openssl/err.h>
#include <sys/select.h>



VPNClient::VPNClient(QObject *parent)
    : QObject(parent), udpServerPort(0), udpReady(false),
    authenticated(false), serverPort(0), clientId(0),
    udpHandshakeTimer(nullptr), tunTrafficTimer(nullptr),
    networkManager(nullptr), totalBytesReceived(0),
    totalBytesSent(0), tlsWrapper(nullptr),
    pendingPacketSize(0), isReadingPacketData(false),
    txCounter(0), rxCounter(0), rxWindowBitmap(0), cryptoReady(false),
    // --- [THÊM KHỞI TẠO] ---
    totalPacketsReceived(0),
    totalDecryptErrors(0)
// -----------------------
{
    socket = new QTcpSocket(this);
    udpSocket = new QUdpSocket(this);

    // OPTIMIZATION: Tăng buffer sizes lên 1MB
    udpSocket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 1048576);
    udpSocket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 1048576);
    socket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 1048576);
    socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 1048576);

    pingTimer = new QTimer(this);
    networkManager = new QNetworkAccessManager(this);

    tlsReadPoller = new QTimer(this);

    encryptCtx = EVP_CIPHER_CTX_new();
    decryptCtx = EVP_CIPHER_CTX_new();

    if (!encryptCtx || !decryptCtx) {
        qCritical() << "[CRYPTO] Failed to create EVP contexts!";
        return;
    }

    qDebug() << "[CRYPTO] Contexts initialized";

    tlsReadPoller->setInterval(10);
    connect(tlsReadPoller, &QTimer::timeout, this, &VPNClient::onReadyRead);

    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);

    connect(udpSocket, &QUdpSocket::readyRead, this, &VPNClient::onUdpReadyRead);

    pingTimer->setInterval(30000);

    tunTrafficTimer = new QTimer(this);
    tunTrafficTimer->setInterval(1);
    connect(tunTrafficTimer, &QTimer::timeout, this, &VPNClient::processTUNTraffic);
}

VPNClient::~VPNClient()
{
    disconnectFromServer();
    if (tlsWrapper) {
        tlsWrapper->cleanup();
        delete tlsWrapper;
        if (encryptCtx) EVP_CIPHER_CTX_free(encryptCtx);
        if (decryptCtx) EVP_CIPHER_CTX_free(decryptCtx);
        tlsWrapper = nullptr;
    }
}

// void VPNClient::connectToServer(const QString& host, int port)
// {
//     if (socket->state() != QAbstractSocket::UnconnectedState) {
//         socket->disconnectFromHost();
//         QThread::msleep(100);
//     }

//     serverHost = host;
//     serverPort = port;
//     authenticated = false;
//     assignedVpnIP.clear();
//     udpReady = false;  // RESET UDP

//     socket->connectToHost(host, port);
// }

void VPNClient::connectToServer(const QString& host, int port)
{
    // 1. Reset trạng thái socket nếu cần
    if (socket->state() != QAbstractSocket::UnconnectedState) {
        socket->disconnectFromHost();
        // Không dùng QThread::msleep ở đây để tránh đơ UI, socket sẽ tự xử lý
    }

    serverHost = host;
    serverPort = port;
    authenticated = false;
    assignedVpnIP.clear();
    udpReady = false;

    // =========================================================================
    // [FIX RECONNECT] Tái thiết lập tín hiệu (Vì đã bị ngắt ở disconnectFromServer)
    // Dùng Qt::UniqueConnection để đảm bảo không bị double-connect
    // =========================================================================

    // 1. Tín hiệu TCP Socket
    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected, Qt::UniqueConnection);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected, Qt::UniqueConnection);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError, Qt::UniqueConnection);

    // Lưu ý: Tín hiệu readyRead sẽ được xử lý riêng trong onConnected hoặc tlsReadPoller,
    // nên ở đây ta có thể connect lại để catch các gói tin handshake ban đầu (nếu cần).
    // Tuy nhiên trong logic hiện tại của bạn, onConnected sẽ disconnect readyRead cũ đi.
    // Để an toàn, cứ connect lại ở đây:
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead, Qt::UniqueConnection);

    // 2. Tín hiệu UDP Socket (Cũng bị ngắt ở disconnectFromServer)
    connect(udpSocket, &QUdpSocket::readyRead, this, &VPNClient::onUdpReadyRead, Qt::UniqueConnection);
    // =========================================================================

    qDebug() << "[CLIENT] Connecting to" << host << ":" << port;
    socket->connectToHost(host, port);
}

void VPNClient::onConnected()
{

    qDebug() << "[TLS] Setting up TLS connection...";

    if (!socket->waitForConnected(5000)) {
        qWarning() << "[TLS] Socket not ready";
        emit error("Connection timeout");
        return;
    }

    // Disconnect Qt's readyRead BEFORE TLS setup
    disconnect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);

    tlsWrapper = new TLSWrapper(false);

    int sockfd = socket->socketDescriptor();
    qWarning() << "[DEBUG] Socket state:" << socket->state();
    qWarning() << "[DEBUG] Socket error:" << socket->errorString();
    if (sockfd == -1) {
        qWarning() << "[TLS] Invalid socket descriptor";
        emit error("Invalid socket");
        return;
    }

    qDebug() << "[TLS] Socket FD:" << sockfd;

    if (!tlsWrapper->initTLS(sockfd)) {
        qWarning() << "[TLS] Handshake failed!";
        emit error("TLS handshake failed");
        delete tlsWrapper;
        tlsWrapper = nullptr;
        socket->disconnectFromHost();
        return;
    }

    qDebug() << "[TLS] ✓ Handshake successful";
    emit connected();

    qDebug() << "[AUTH] Sending credentials...";
    authenticate();

    // ========================================
    // STEP 1: Read AUTH_OK response
    // ========================================
    qDebug() << "[AUTH] Waiting for AUTH response...";

    char buffer[4096];
    int maxRetries = 30;
    int retries = 0;
    bool authReceived = false;

    while (retries < maxRetries && !authReceived) {
        QThread::msleep(100);

        int bytesRead = tlsWrapper->recv(buffer, sizeof(buffer));

        if (bytesRead > 0) {
            messageBuffer.append(QByteArray(buffer, bytesRead));

            // Look for complete AUTH message
            int newlinePos = messageBuffer.indexOf('\n');
            if (newlinePos != -1) {
                QByteArray line = messageBuffer.left(newlinePos);
                messageBuffer.remove(0, newlinePos + 1);

                QString message = QString::fromUtf8(line).trimmed();
                if (message.startsWith("AUTH_OK|") || message.startsWith("AUTH_FAIL|")) {
                    qDebug() << "[AUTH] Received:" << message;
                    parseServerMessage(message);
                    emit messageReceived(message);
                    authReceived = true;
                    break;
                }
            }
        } else if (bytesRead < 0) {
            int sslError = SSL_get_error(tlsWrapper->getSSL(), bytesRead);
            if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE) {
                qWarning() << "[AUTH] SSL error:" << sslError;
                break;
            }
        }

        retries++;
    }

    if (!authReceived) {
        qWarning() << "[AUTH] Timeout";
        emit error("Authentication timeout");
        socket->disconnectFromHost();
        return;
    }

    if (!authenticated) {
        qWarning() << "[AUTH] Failed";
        return;
    }

    qDebug() << "[AUTH] ✓ Authenticated";

    // ========================================
    // STEP 2: Request and read UDP_KEY
    // ========================================
    qDebug() << "[CRYPTO] Requesting UDP encryption key...";
    requestUDPKey();  // ← CHỈ GỌI 1 LẦN Ở ĐÂY

    qDebug() << "[CRYPTO] Waiting for UDP_KEY...";

    maxRetries = 50;  // Tăng timeout lên 5 giây
    retries = 0;
    bool keyReceived = false;

    while (retries < maxRetries && !keyReceived) {
        QThread::msleep(100);

        int bytesRead = tlsWrapper->recv(buffer, sizeof(buffer));

        if (bytesRead > 0) {
            messageBuffer.append(QByteArray(buffer, bytesRead));

            qDebug() << "[DEBUG] Buffer size:" << messageBuffer.size()
                     << "bytes, looking for UDP_KEY...";

            // Look for UDP_KEY header
            int keyPos = messageBuffer.indexOf("UDP_KEY|");
            if (keyPos != -1) {
                qDebug() << "[DEBUG] Found UDP_KEY| at position" << keyPos;

                // Need at least 41 bytes: "UDP_KEY|" (😎 + key (32) + "\n" (1)
                if (messageBuffer.size() >= (keyPos + 41)) {
                    QByteArray keyPacket = messageBuffer.mid(keyPos, 41);

                    // Verify format
                    if (keyPacket.size() == 41 && keyPacket[40] == '\n') {
                        QByteArray keyData = keyPacket.mid(8, 32);

                        qDebug() << "[CRYPTO] ✓ Received UDP_KEY:" << keyData.size() << "bytes";

                        // Setup crypto immediately
                        setupRawUDPKey(keyData);

                        // Remove processed packet
                        messageBuffer.remove(keyPos, 41);
                        keyReceived = true;
                        break;
                    } else {
                        qWarning() << "[CRYPTO] Malformed UDP_KEY packet";
                        messageBuffer.remove(keyPos, 8); // Remove header, retry
                    }
                } else {
                    qDebug() << "[DEBUG] Waiting for more data... (need 41 bytes)";
                }
            }
        } else if (bytesRead < 0) {
            int sslError = SSL_get_error(tlsWrapper->getSSL(), bytesRead);
            if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE) {
                qWarning() << "[CRYPTO] SSL error:" << sslError;
                break;
            }
        }

        retries++;
    }

    if (!keyReceived) {
        qWarning() << "[CRYPTO] ✗ UDP_KEY timeout";
        qWarning() << "[DEBUG] Buffer content:" << messageBuffer.toHex();
        emit error("UDP key timeout");
        socket->disconnectFromHost();
        return;
    }

    qDebug() << "[CRYPTO] ✓ UDP_KEY processed";

    // ========================================
    // STEP 3: Setup async message handling
    // ========================================
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);

    if (!tlsReadPoller) {
        tlsReadPoller = new QTimer(this);
        connect(tlsReadPoller, &QTimer::timeout, this, &VPNClient::onReadyRead);
    }
    tlsReadPoller->setInterval(50);
    tlsReadPoller->start();

    qDebug() << "[TLS] ✓ Connection fully established";
}

// void VPNClient::disconnectFromServer()
// {
//     qDebug() << "[CLIENT] Disconnecting safely...";

//     // 1. NGẮT KẾT NỐI TÍN HIỆU NGAY LẬP TỨC
//     if (socket) {
//         socket->disconnect(this); // Ngăn onReadyRead được gọi lại
//     }
//     if (tlsReadPoller) tlsReadPoller->stop();
//     if (tunTrafficTimer) tunTrafficTimer->stop();
//     if (pingTimer) pingTimer->stop();
//     if (udpHandshakeTimer) udpHandshakeTimer->stop();

//     // 2. Gửi lệnh ngắt kết nối (Best effort)
//     if (tlsWrapper && socket->state() == QAbstractSocket::ConnectedState) {
//         tlsWrapper->send("DISCONNECT\n", 11);
//         QThread::msleep(10); // Đợi flush nhẹ
//     }

//     // 3. Hủy TLS Wrapper và đặt về nullptr
//     if (tlsWrapper) {
//         tlsWrapper->cleanup();
//         delete tlsWrapper;
//         tlsWrapper = nullptr; // QUAN TRỌNG: Đặt về null để check trong onReadyRead
//     }

//     // 4. Đóng Socket
//     if (socket) {
//         socket->abort();
//         socket->close();
//     }

//     // Reset UDP socket để xóa buffer cũ (Fix lỗi Decrypt Fail khi reconnect)
//     if (udpSocket) {
//         udpSocket->abort();
//         udpSocket->close();
//         // Không delete udpSocket vì nó là con của QObject this,
//         // nhưng cần bind lại khi connect mới.
//     }

//     // ... (Cleanup TUN, reset biến)
//     authenticated = false;
//     udpReady = false;
//     cryptoReady = false;

//     emit disconnected();
// }

// Trong vpn_client.cpp

void VPNClient::disconnectFromServer()
{
    qDebug() << "[CLIENT] Disconnecting safely...";

    // [FIX 1] QUAN TRỌNG NHẤT: Đặt cờ này false đầu tiên để chặn processTUNTraffic và sendPacket
    authenticated = false;
    udpReady = false;
    cryptoReady = false;

    // 1. Ngắt tất cả Timer ngay lập tức
    if (tlsReadPoller) tlsReadPoller->stop();
    if (tunTrafficTimer) tunTrafficTimer->stop();
    if (pingTimer) pingTimer->stop();
    if (udpHandshakeTimer) udpHandshakeTimer->stop();

    // 2. Ngắt kết nối tín hiệu socket (ngăn onReadyRead được gọi)
    if (socket) {
        socket->disconnect(this);
    }

    // 3. Ngắt kết nối tín hiệu UDP (ngăn onUdpReadyRead được gọi)
    if (udpSocket) {
        udpSocket->disconnect(this);
    }

    // 4. Gửi lệnh ngắt kết nối qua TLS (nếu còn sống)
    if (tlsWrapper && socket && socket->state() == QAbstractSocket::ConnectedState) {
        tlsWrapper->send("DISCONNECT\n", 11);
        // Không sleep ở đây để tránh giao diện bị đơ, data gửi đi hay không không quan trọng lúc này
    }

    // 5. Hủy TLS Wrapper (An toàn vì authenticated = false đã chặn các hàm khác dùng nó)
    if (tlsWrapper) {
        tlsWrapper->cleanup();
        delete tlsWrapper;
        tlsWrapper = nullptr;
    }

    // 6. Đóng Socket TCP
    if (socket) {
        socket->abort();
        socket->close();
    }

    // 7. Đóng Socket UDP
    if (udpSocket) {
        udpSocket->abort();
        udpSocket->close();
    }

    // 8. Đóng TUN (Lệnh này chạy system() nên để cuối cùng trước khi emit)
    if (tun.isOpened()) {
        tun.close();
    }

    // Reset counters
    txCounter.store(0);
    rxCounter.store(0);
    rxWindowBitmap.store(0);

    emit disconnected();
}

bool VPNClient::isConnected() const
{
    return socket->state() == QAbstractSocket::ConnectedState && authenticated;
}

void VPNClient::startTUNTrafficGeneration()
{
    if (authenticated && tunTrafficTimer) {
        tunTrafficTimer->start(1);  // Từ 5ms -> 1ms
    }
}

void VPNClient::stopTUNTrafficGeneration()
{
    if (tunTrafficTimer) tunTrafficTimer->stop();
}

void VPNClient::processTUNTraffic()
{
    if (!authenticated || !tun.isOpened()) return;

    char buffer[4096];  // Tăng từ 2000 lên 4096
    int packetsRead = 0;

    // OPTIMIZATION: Đọc tối đa 50 packets thay vì 20
    while (packetsRead < 50) {
        int n = tun.readPacket(buffer, sizeof(buffer));
        if (n <= 0) break;
        sendPacketToServer(QByteArray(buffer, n));

        packetsRead++;
    }

    // OPTIMIZATION: Chỉ emit stats mỗi 100 packets
    static int statsCounter = 0;
    if (++statsCounter >= 100) {
        emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
        statsCounter = 0;
    }
}

// UPDATE sendPacketToServer - ENCRYPT BEFORE SEND:
// void VPNClient::sendPacketToServer(const QByteArray& packetData)
// {
//     if (!authenticated || !cryptoReady || packetData.size() > 1500) return;

//     // ✅ ENCRYPT PACKET
//     QByteArray encryptedData;
//     if (!encryptPacket(packetData, encryptedData)) {
//         static int failCount = 0;
//         if (++failCount % 100 == 0) {
//             qWarning() << "[CRYPTO] Encryption failures:" << failCount;
//         }
//         return;
//     }

//     // UDP first
//     if (udpReady && udpSocket->state() == QAbstractSocket::BoundState) {
//         int totalSize = 8 + encryptedData.size();
//         QByteArray udpPacket(totalSize, 0);

//         *(qint32*)udpPacket.data() = clientId;
//         *(qint32*)(udpPacket.data() + 4) = encryptedData.size();
//         memcpy(udpPacket.data() + 8, encryptedData.constData(), encryptedData.size());

//         qint64 sent = udpSocket->writeDatagram(udpPacket, udpServerAddr, udpServerPort);

//         if (sent > 0) {
//             totalBytesSent += packetData.size(); // Original size for stats
//             return;
//         }
//     }

//     // TCP fallback (cũng encrypted)
//     QString header = QString("PACKET_DATA|%1\n").arg(encryptedData.size());
//     socket->write(header.toUtf8());
//     socket->write(encryptedData);
// }
void VPNClient::sendPacketToServer(const QByteArray& packetData)
{
    if (!authenticated || !cryptoReady || packetData.size() > 1500) return;

    // Encrypt Packet
    QByteArray encryptedData;
    if (!encryptPacket(packetData, encryptedData)) {
        return;
    }

    // Ưu tiên gửi UDP
    if (udpReady && udpSocket->state() == QAbstractSocket::BoundState) {
        // ... (Code UDP giữ nguyên) ...
        int totalSize = 8 + encryptedData.size();
        QByteArray udpPacket(totalSize, 0);
        *(qint32*)udpPacket.data() = clientId;
        *(qint32*)(udpPacket.data() + 4) = encryptedData.size();
        memcpy(udpPacket.data() + 8, encryptedData.constData(), encryptedData.size());

        if (udpSocket->writeDatagram(udpPacket, udpServerAddr, udpServerPort) > 0) {
            totalBytesSent += packetData.size();
            return;
        }
    }

    // TCP Fallback: [FIX] PHẢI DÙNG tlsWrapper->send, KHÔNG ĐƯỢC DÙNG socket->write
    if (tlsWrapper) {
        QString header = QString("PACKET_DATA|%1\n").arg(encryptedData.size());
        QByteArray headerBytes = header.toUtf8();

        // Gửi Header qua TLS
        tlsWrapper->send(headerBytes.constData(), headerBytes.size());
        // Gửi Data qua TLS
        tlsWrapper->send(encryptedData.constData(), encryptedData.size());

        totalBytesSent += packetData.size();
    }
}

// UPDATE onUdpReadyRead - DECRYPT RECEIVED PACKETS:
void VPNClient::onUdpReadyRead()
{
    int packetsProcessed = 0;

    while (udpSocket->hasPendingDatagrams() && packetsProcessed < 100) {
        QByteArray datagram;
        datagram.resize(udpSocket->pendingDatagramSize());

        QHostAddress sender;
        quint16 senderPort;
        qint64 size = udpSocket->readDatagram(datagram.data(), datagram.size(),
                                              &sender, &senderPort);
        if (size < 8) continue;

        qint32 recvClientId = *(qint32*)datagram.data();
        qint32 encryptedSize = *(qint32*)(datagram.data() + 4);

        if (recvClientId == clientId && encryptedSize == 0) {
            if (udpHandshakeTimer && udpHandshakeTimer->isActive()) {
                udpHandshakeTimer->stop();
                delete udpHandshakeTimer;
                udpHandshakeTimer = nullptr;
                udpReady = true;
                qDebug() << "[UDP] ✓ Handshake completed";
            }
            continue;
        }

        if (recvClientId == clientId && encryptedSize > 0 && encryptedSize < 65536) {
            if (datagram.size() >= (8 + encryptedSize)) {
                QByteArray encryptedPacket = datagram.mid(8, encryptedSize);
                QByteArray plainPacket;

                if (decryptPacket(encryptedPacket, plainPacket)) {
                    int written = tun.writePacket(plainPacket.constData(),
                                                  plainPacket.size());
                    if (written > 0) {
                        totalBytesReceived += written;
                        packetsProcessed++;
                        totalPacketsReceived++;
                    }
                } else {
                    totalDecryptErrors++;
                    static int decryptFail = 0;
                    if (++decryptFail % 100 == 0) {
                        qWarning() << "[SECURITY] Rejected" << decryptFail
                                   << "tampered packets";
                    }
                }
            }
        }
    }
}

// Thay thế hàm parseServerMessage() trong vpn_client.cpp:
void VPNClient::parseServerMessage(const QString& message)
{
    qDebug() << "[PARSE] Received:" << message;

    if (message.startsWith("AUTH_OK|")) {
        authenticated = true;
        pingTimer->start();

        // ✅ Parse VPN_IP
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            assignedVpnIP = message.mid(start, end - start).trimmed();
            qDebug() << "[CONFIG] Assigned VPN IP:" << assignedVpnIP;
            emit vpnIPAssigned(assignedVpnIP);
        }

        // ✅ Parse UDP_PORT
        if (message.contains("UDP_PORT:")) {
            int start = message.indexOf("UDP_PORT:") + 9;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            QString portStr = message.mid(start, end - start).trimmed();
            udpServerPort = portStr.toUShort();
            udpServerAddr = QHostAddress(serverHost);
            qDebug() << "[CONFIG] UDP Server Port:" << udpServerPort;
        }

        // ✅ Parse CLIENT_ID
        if (message.contains("CLIENT_ID:")) {
            int start = message.indexOf("CLIENT_ID:") + 10;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            QString idStr = message.mid(start, end - start).trimmed();
            clientId = idStr.toInt();
            qDebug() << "[CONFIG] Client ID:" << clientId;
        }

        // ❌ XÓA DÒNG NÀY - KHÔNG GỌI requestUDPKey() Ở ĐÂY
        // qDebug() << "[CRYPTO] Requesting UDP encryption key...";
        // requestUDPKey(); // ← XÓA HOẶC COMMENT

        emit authenticationResult(true, message.mid(8));
    }
    else if (message.startsWith("UDP_KEY_FAIL|")) {
        qWarning() << "[CRYPTO] Server error:" << message.mid(13);
        emit error("UDP key setup failed");
    }
    else if (message.startsWith("AUTH_FAIL|")) {
        authenticated = false;
        emit authenticationResult(false, message.mid(10));
    }
    else if (message.startsWith("STATUS|")) {
        emit statusReceived(message.mid(7));
    }
    else if (message.startsWith("ERROR|")) {
        emit error(message.mid(6));
    }
    else if (message.startsWith("PONG|")) {
        qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
        int latency = currentTime - m_pingSentTime;
        if (latency < 0) latency = 0;

        qDebug() << "[PING] Latency:" << latency << "ms";
        emit pingUpdated(latency);
    }
}

void VPNClient::requestUDPKey()
{
    qDebug() << "[CRYPTO] Requesting UDP encryption key...";
    sendMessage("UDP_KEY_REQUEST");
}

void VPNClient::startUdpHandshake()
{
    qDebug() << "[UDP] Starting handshake...";

    if (udpHandshakeTimer) {
        udpHandshakeTimer->stop();
        delete udpHandshakeTimer;
    }

    udpHandshakeTimer = new QTimer(this);
    udpHandshakeTimer->setSingleShot(false);
    connect(udpHandshakeTimer, &QTimer::timeout, this, &VPNClient::sendUdpHandshake);

    sendUdpHandshake();

    // OPTIMIZATION: Giảm từ 500ms xuống 200ms
    udpHandshakeTimer->start(200);
}

void VPNClient::sendUdpHandshake()
{
    if (!udpSocket || udpServerPort == 0 || udpServerAddr.isNull()) return;

    char handshake[8];
    memset(handshake, 0, 8);

    *(qint32*)handshake = clientId;
    *(qint32*)(handshake + 4) = 0;

    qint64 sent = udpSocket->writeDatagram(handshake, 8, udpServerAddr, udpServerPort);

    // OPTIMIZATION: Chỉ log lỗi, không log thành công
    if (sent <= 0) {
        qWarning() << "[UDP] Handshake send failed:" << udpSocket->errorString();
    }
}

void VPNClient::onReadyRead() {
    if (!tlsWrapper || !socket || socket->state() != QAbstractSocket::ConnectedState) return;

    char buffer[8192];
    int bytesRead = tlsWrapper->recv(buffer, sizeof(buffer));

    if (bytesRead > 0) {
        messageBuffer.append(QByteArray(buffer, bytesRead));
    }

    // Xử lý buffer liên tục cho đến khi hết lệnh hoàn chỉnh
    while (!messageBuffer.isEmpty()) {
        if (messageBuffer.startsWith("UDP_KEY|")) {
            if (messageBuffer.size() >= 40) {
                QByteArray keyData = messageBuffer.mid(8, 32);
                int toRemove = 40;
                if (messageBuffer.size() > 40 && messageBuffer.at(40) == '\n') toRemove++;
                messageBuffer.remove(0, toRemove);
                setupRawUDPKey(keyData);
                continue;
            } else break;
        }

        int newlinePos = messageBuffer.indexOf('\n');
        if (newlinePos != -1) {
            QByteArray line = messageBuffer.left(newlinePos);
            messageBuffer.remove(0, newlinePos + 1);
            QString message = QString::fromUtf8(line).trimmed();
            if (!message.isEmpty()) parseServerMessage(message);
        } else break;
    }
}

void VPNClient::setupRawUDPKey(const QByteArray& keyData) {
    if (keyData.size() != 32) {
        qWarning() << "[CRYPTO] Invalid key size received:" << keyData.size();
        return;
    }

    // Reset counters để đồng bộ với Server
    txCounter.store(0);
    rxCounter.store(0);
    rxWindowBitmap.store(0);

    {
        std::lock_guard<std::mutex> lock(encryptMutex);
        sharedKey.assign(keyData.begin(), keyData.end());
        // Reset encrypt context để áp dụng key mới
        if (encryptCtx) EVP_CIPHER_CTX_reset(encryptCtx);
    }

    {
        std::lock_guard<std::mutex> lock(decryptMutex);
        if (decryptCtx) EVP_CIPHER_CTX_reset(decryptCtx);
    }

    cryptoReady = true;
    qDebug() << "[CRYPTO] ✓ UDP encryption ready (Raw 32-byte mode)";

    // Sau khi có Key, bắt đầu kích hoạt UDP Handshake
    setupUDPConnection();
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

void VPNClient::authenticate()
{
    sendMessage(QString("AUTH"));
}

void VPNClient::sendMessage(const QString& message)
{
    if (!tlsWrapper) {
        qWarning() << "[TLS] No TLS wrapper available";
        return;
    }

    QString msg = message;
    if (!msg.endsWith('\n')) msg += '\n';

    QByteArray data = msg.toUtf8();
    int sent = tlsWrapper->send(data.constData(), data.size());

    if (sent <= 0) {
        qWarning() << "[TLS] Send failed";
    }
}

bool VPNClient::encryptPacket(const QByteArray& plain, QByteArray& encrypted)
{
    // Kiểm tra điều kiện đầu vào
    if (!cryptoReady || sharedKey.empty() || !encryptCtx) {
        return false;
    }

    std::lock_guard<std::mutex> lock(encryptMutex);

    // 1. Tạo IV (Nonce) - 12 bytes
    uint8_t iv[12];
    uint64_t counter = txCounter.fetch_add(1, std::memory_order_relaxed);
    memcpy(iv, &counter, 8);
    memset(iv + 8, 0, 4);

    // === [FIX 3] Cấp phát và lấy con trỏ an toàn ===
    int plainLen = plain.size();
    int maxCipherLen = plainLen + 16; // GCM thường ra size bằng input

    // ==========================================================
    // [FIX QUAN TRỌNG NHẤT] Cấp phát bộ nhớ TRƯỚC khi lấy con trỏ
    // Cấu trúc: [IV:12] + [TAG:16] + [CIPHERTEXT:N]
    // ==========================================================
    encrypted.resize(28 + plainLen);

    // Bây giờ lấy con trỏ mới an toàn
    uint8_t* outBuf = reinterpret_cast<uint8_t*>(encrypted.data());
    uint8_t* ivPtr = outBuf;
    uint8_t* tagPtr = outBuf + 12;
    uint8_t* cipherPtr = outBuf + 28;

    // 2. Reset Context (Bắt buộc để tránh lỗi từ gói tin trước)
    if (EVP_CIPHER_CTX_reset(encryptCtx) != 1) {
        std::cerr << "[CRITICAL] Encrypt Reset failed\n";
        return false;
    }

    // 3. Khởi tạo thuật toán
    if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        qWarning() << "[CRYPTO] Init Cipher failed";
        return false;
    }

    // 4. Set IV Length (12 bytes)
    if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        qWarning() << "[CRYPTO] Set IV len failed";
        return false;
    }

    // 5. Set Key và IV
    if (EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, sharedKey.data(), iv) != 1) {
        qWarning() << "[CRYPTO] Set Key/IV failed";
        return false;
    }

    // 6. Mã hóa dữ liệu
    int len = 0;
    int cipherLen = 0;

    if (EVP_EncryptUpdate(encryptCtx, cipherPtr, &len,
                          reinterpret_cast<const uint8_t*>(plain.constData()), plainLen) != 1) {
        qWarning() << "[CRYPTO] Encrypt Update failed";
        return false;
    }
    cipherLen = len;

    if (EVP_EncryptFinal_ex(encryptCtx, cipherPtr + len, &len) != 1) {
        qWarning() << "[CRYPTO] Encrypt Final failed";
        return false;
    }
    cipherLen += len;

    // 7. Lấy Tag
    if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_GET_TAG, 16, tagPtr) != 1) {
        qWarning() << "[CRYPTO] Get Tag failed";
        return false;
    }

    // 8. Copy IV vào đầu gói tin (Bây giờ đã an toàn)
    memcpy(ivPtr, iv, 12);

    // Resize lại đúng kích thước thực tế (thường GCM không padding nên size giữ nguyên)
    encrypted.resize(28 + cipherLen);

    // In log debug ra stderr để đảm bảo hiển thị ngay cả khi crash (dù đã fix crash)
    // std::cerr << "[DEBUG] Encrypted packet size: " << encrypted.size() << std::endl;

    return true;
}

// ============================================================================
// 🔧 FIX 3: CORRECT decryptPacket() with Sliding Window
// ============================================================================
bool VPNClient::decryptPacket(const QByteArray& encrypted, QByteArray& plain)
{
    if (sharedKey.empty() || !decryptCtx || encrypted.size() < 28) {
        return false;
    }

    // Thread safety
    std::lock_guard<std::mutex> lock(decryptMutex);

    // Parse packet structure
    const uint8_t* data = reinterpret_cast<const uint8_t*>(encrypted.constData());
    const uint8_t* iv = data;
    const uint8_t* tag = data + 12;
    const uint8_t* ciphertext = data + 28;
    int cipherLen = encrypted.size() - 28;

    // ✅ CRITICAL: Anti-Replay with Sliding Window (like server)
    uint64_t nonce = 0;
    memcpy(&nonce, iv, 8);

    uint64_t currentCounter = rxCounter.load(std::memory_order_acquire);

    if (nonce > currentCounter) {
        // New packet - update window
        uint64_t diff = nonce - currentCounter;

        if (diff < 64) {
            uint64_t bitmap = rxWindowBitmap.load();
            bitmap <<= diff;
            bitmap |= 1;
            rxWindowBitmap.store(bitmap, std::memory_order_release);
        } else {
            rxWindowBitmap.store(1, std::memory_order_release);
        }

        rxCounter.store(nonce, std::memory_order_release);

    } else {
        // Check if already received
        uint64_t diff = currentCounter - nonce;

        if (diff >= 64) {
            // Too old
            static int replayCount = 0;
            if (++replayCount % 100 == 0) {
                qDebug() << "[CRYPTO] Rejected" << replayCount << "old packets";
            }
            return false;
        }

        uint64_t bit = 1ULL << diff;
        uint64_t bitmap = rxWindowBitmap.load(std::memory_order_acquire);

        if ((bitmap & bit) != 0) {
            // Duplicate
            static int dupCount = 0;
            if (++dupCount % 100 == 0) {
                qDebug() << "[CRYPTO] Rejected" << dupCount << "duplicate packets";
            }
            return false;
        }

        // Mark as received
        bitmap |= bit;
        rxWindowBitmap.store(bitmap, std::memory_order_release);
    }

    // Prepare plaintext buffer
    plain.resize(cipherLen + 16);  // Extra space for safety
    int len = 0;
    int plainLen = 0;

    if (EVP_CIPHER_CTX_reset(decryptCtx) != 1) {
        std::cerr << "[CRITICAL] Decrypt Reset failed\n";
        return false;
    }

    // ✅ CRITICAL: Initialize cipher CORRECTLY
    // Step 1: Reset to AES-256-GCM
    if (EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1) {
        qWarning() << "[CRYPTO] Reset decrypt cipher failed";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Step 2: Set IV length
    if (EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_IVLEN,
                            12, nullptr) != 1) {
        qWarning() << "[CRYPTO] Set decrypt IV length failed";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Step 3: Set key and IV
    if (EVP_DecryptInit_ex(decryptCtx, nullptr, nullptr,
                           sharedKey.data(), iv) != 1) {
        qWarning() << "[CRYPTO] Set decrypt key/IV failed";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Decrypt Update
    if (EVP_DecryptUpdate(decryptCtx,
                          reinterpret_cast<uint8_t*>(plain.data()),
                          &len, ciphertext, cipherLen) != 1) {
        qWarning() << "[CRYPTO] Decrypt Update failed";
        ERR_print_errors_fp(stderr);
        return false;
    }
    plainLen = len;

    // Set Tag for verification
    if (EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_TAG,
                            16, (void*)tag) != 1) {
        qWarning() << "[CRYPTO] Set TAG failed";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Decrypt Final (verifies tag)
    int ret = EVP_DecryptFinal_ex(decryptCtx,
                                  reinterpret_cast<uint8_t*>(plain.data()) + len,
                                  &len);

    if (ret > 0) {
        plainLen += len;
        plain.resize(plainLen);

        // Debug log first few decryptions
        static int debugCount = 0;
        if (debugCount < 5) {
            qDebug() << "[CRYPTO] Decrypted:" << encrypted.size() << "→"
                     << plainLen << "bytes (Nonce:" << nonce << ")";
            debugCount++;
        }

        return true;
    } else {
        // Tag verification failed
        static int tagFailCount = 0;
        if (++tagFailCount % 100 == 0) {
            qWarning() << "[CRYPTO] Tag verification failed" << tagFailCount << "times";
            ERR_print_errors_fp(stderr);
        }
        return false;
    }
}

void VPNClient::setupUDPConnection()
{
    // Bind UDP socket
    if (udpSocket->state() != QAbstractSocket::BoundState) {
        if (udpSocket->bind(QHostAddress::AnyIPv4, 0)) {
            qDebug() << "[UDP] Bound to local port" << udpSocket->localPort();
        } else {
            qWarning() << "[UDP] Bind failed:" << udpSocket->errorString();
            return;
        }
    }

    // Start UDP handshake
    if (udpServerPort > 0 && !udpServerAddr.isNull()) {
        qDebug() << "[UDP] Starting handshake...";
        startUdpHandshake();
        QThread::msleep(200);
    }

    // Setup TUN interface
    if (!tun.isOpened() && tun.create()) {
        if (tun.configure(assignedVpnIP.toStdString(),
                          "255.255.255.0",
                          serverHost.toStdString())) {
            qDebug() << "[TUN] ✓ Configured successfully";
            startTUNTrafficGeneration();
        } else {
            qWarning() << "[TUN] Configuration failed";
        }
    } else if (tun.isOpened()) {
        qDebug() << "[TUN] Already opened, starting traffic";
        startTUNTrafficGeneration();
    }
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

// --- [THÊM MỚI] Hàm gửi Ping ---
void VPNClient::sendPing()
{
    if (authenticated) {
        m_pingSentTime = QDateTime::currentMSecsSinceEpoch();
        sendMessage("PING");
    }
}

// --- [THÊM MỚI] Hàm tính Packet Loss ---
double VPNClient::getPacketLoss() {
    if (totalPacketsReceived == 0) return 0.0;
    // Công thức: (Lỗi / (Tổng nhận + Lỗi)) * 100
    return ((double)totalDecryptErrors / (double)(totalPacketsReceived + totalDecryptErrors)) * 100.0;
}
