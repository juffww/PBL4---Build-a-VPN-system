#include <QRandomGenerator>
#include <QDateTime>
#include "vpn_client.h"
// #include "crypto_client.h" // Không còn cần thiết nếu bạn đã xóa crypto_client.h
#include <QHostAddress>
#include <QDebug>
#include <QThread>
#include <cstring>
#include <QRegularExpression>
#include <openssl/err.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h>
#endif

static std::string getOpenSSLError() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

VPNClient::VPNClient(QObject *parent)
    : QObject(parent), udpServerPort(0), udpReady(false),
    authenticated(false), serverPort(0), clientId(0),
    udpHandshakeTimer(nullptr), tunTrafficTimer(nullptr),
    networkManager(nullptr), totalBytesReceived(0),
    totalBytesSent(0), tlsWrapper(nullptr),
    pendingPacketSize(0), isReadingPacketData(false), cryptoReady(false),
    txCounter(0), rxCounter(0), rxWindowBitmap(0)
{
    socket = new QTcpSocket(this);
    udpSocket = new QUdpSocket(this);

    int bufferSize = 4 * 1024 * 1024;
    // udpSocket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 1048576);
    // udpSocket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 1048576);
    // socket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 1048576);
    // socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 1048576);
    udpSocket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, bufferSize);
    udpSocket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, bufferSize);
    socket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, bufferSize);
    socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, bufferSize);

    pingTimer = new QTimer(this);
    networkManager = new QNetworkAccessManager(this);

    tlsReadPoller = new QTimer(this);
    tlsReadPoller->setInterval(10);

    // Khởi tạo context một lần
    encryptCtx = EVP_CIPHER_CTX_new();
    decryptCtx = EVP_CIPHER_CTX_new();

    // Tốt nhất nên kiểm tra null
    if (!encryptCtx || !decryptCtx) {
        qWarning() << "[CRYPTO] Failed to create EVP contexts";
    }

    connect(tlsReadPoller, &QTimer::timeout, this, &VPNClient::onReadyRead);

    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);
    //connect(pingTimer, &QTimer::timeout, this, &VPNClient::sendPing);
    connect(udpSocket, &QUdpSocket::readyRead, this, &VPNClient::onUdpReadyRead);

    pingTimer->setInterval(30000);

    // OPTIMIZATION: Giảm timer interval xuống 1ms cho throughput cao hơn
    tunTrafficTimer = new QTimer(this);
    tunTrafficTimer->setInterval(1);  // Từ 10ms -> 1ms
    connect(tunTrafficTimer, &QTimer::timeout, this, &VPNClient::processTUNTraffic);

}

VPNClient::~VPNClient()
{
    disconnectFromServer();
    if (tlsWrapper) {
        tlsWrapper->cleanup();
        delete tlsWrapper;
        tlsWrapper = nullptr;
    }

    // Giải phóng context một lần
    if (encryptCtx) EVP_CIPHER_CTX_free(encryptCtx);
    if (decryptCtx) EVP_CIPHER_CTX_free(decryptCtx);
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

    qDebug() << "[TLS] Setting up TLS connection...";

    if (!socket->waitForConnected(5000)) {
        qWarning() << "[TLS] Socket not ready";
        emit error("Connection timeout");
        return;
    }

    disconnect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);

    tlsWrapper = new TLSWrapper(false);

    int sockfd = socket->socketDescriptor();
    if (sockfd == -1) {
        qWarning() << "[TLS] Invalid socket descriptor";
        emit error("Invalid socket");
        return;
    }

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

    if (!username.isEmpty() && !password.isEmpty()) {
        qDebug() << "[AUTH] Sending credentials...";
        authenticate(username, password);

        char buffer[4096];
        int totalRead = 0;
        int maxRetries = 50;
        int retries = 0;
        bool authReceived = false;
        bool keyReceived = false;

        while (retries < maxRetries && (!authReceived || !keyReceived)) {
            QThread::msleep(100);

            int bytesRead = tlsWrapper->recv(buffer, sizeof(buffer));

            if (bytesRead > 0) {
                messageBuffer.append(QByteArray(buffer, bytesRead));
                totalRead += bytesRead;

                qDebug() << "[AUTH] Buffer size:" << messageBuffer.size() << "bytes";

                // Check for AUTH_OK
                if (!authReceived) {
                    int authPos = messageBuffer.indexOf("AUTH_OK|");
                    if (authPos != -1) {
                        int newlinePos = messageBuffer.indexOf('\n', authPos);
                        if (newlinePos != -1) {
                            QByteArray authLine = messageBuffer.mid(authPos, newlinePos - authPos);
                            QString authMsg = QString::fromUtf8(authLine).trimmed();

                            qDebug() << "[AUTH] Received:" << authMsg;
                            parseServerMessage(authMsg);
                            emit messageReceived(authMsg);
                            authReceived = true;
                        }
                    }
                }

                int udpKeyPos = messageBuffer.indexOf("UDP_KEY|");
                if (udpKeyPos != -1) {
                    // Tìm ký tự xuống dòng thay vì fix cứng độ dài
                    int newlinePos = messageBuffer.indexOf('\n', udpKeyPos);

                    if (newlinePos != -1) {
                        // Cắt dòng chứa key
                        QByteArray keyLine = messageBuffer.mid(udpKeyPos, newlinePos - udpKeyPos);

                        qDebug() << "[CRYPTO] Found UDP_KEY line:" << keyLine;

                        // Xóa khỏi buffer
                        messageBuffer.remove(udpKeyPos, newlinePos - udpKeyPos + 1);

                        if (keyLine.size() > 8) {
                            // Lấy phần Base64 (Bỏ "UDP_KEY|")
                            QByteArray b64Key = keyLine.mid(8);

                            // Giải mã Base64 -> Binary
                            QByteArray keyData = QByteArray::fromBase64(b64Key);

                            if (keyData.size() == 32) {
                                sharedKey.assign(keyData.begin(), keyData.end());
                                cryptoReady = true;
                                txCounter = 0;
                                rxCounter = 0;
                                rxWindowBitmap = 0;

                                qDebug() << "[CRYPTO] ✓ UDP encryption ready (Base64 decoded)";
                                keyReceived = true; // Đánh dấu đã nhận thành công
                            } else {
                                qWarning() << "[CRYPTO] Invalid key size after decode:" << keyData.size();
                            }
                        }
                    }
                }

                if (authReceived && keyReceived) break;
            }
            else if (bytesRead < 0) {
                int sslError = SSL_get_error(tlsWrapper->getSSL(), bytesRead);
                if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE) {
                    qWarning() << "[AUTH] SSL error:" << sslError;
                    break;
                }
            }

            retries++;
        }

        if (!authReceived) {
            qWarning() << "[AUTH] ✗ No AUTH response";
            emit error("Authentication timeout");
            socket->disconnectFromHost();
            return;
        }

        if (!keyReceived) {
            qWarning() << "[CRYPTO] ✗ No UDP_KEY received";
            emit error("UDP key timeout");
            socket->disconnectFromHost();
            return;
        }

        qDebug() << "[AUTH] ✓ Both AUTH and UDP_KEY processed";

        setupUDPConnection();

    } else {
        qWarning() << "[AUTH] No credentials";
        emit error("Missing credentials");
        return;
    }

    // Reconnect readyRead for future messages
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);

    // tlsReadPoller->setInterval(50);
    // tlsReadPoller->start();

    qDebug() << "[TLS] ✓ Connection fully established";
}

void VPNClient::disconnectFromServer()
{

    pingTimer->stop();
    if (tunTrafficTimer) tunTrafficTimer->stop();
    if (tlsReadPoller) tlsReadPoller->stop();

    if (udpHandshakeTimer && udpHandshakeTimer->isActive()) {
        udpHandshakeTimer->stop();
        delete udpHandshakeTimer;
        udpHandshakeTimer = nullptr;
    }

    authenticated = false;
    udpReady = false;
    cryptoReady = false;
    sharedKey.clear();
    txCounter = 0;
    rxCounter = 0;
    rxWindowBitmap = 0;

    // ✓ CLEANUP TLS
    if (tlsWrapper) {
        tlsWrapper->cleanup();
        delete tlsWrapper;
        tlsWrapper = nullptr;
    }

    if (udpSocket->state() == QAbstractSocket::BoundState) {
        udpSocket->close();
    }

    if (tun.isOpened()) {
        tun.setIPv6Status(true);
        tun.close();
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
        tunTrafficTimer->start(1);  // Từ 5ms -> 1ms
    }
}

void VPNClient::stopTUNTrafficGeneration()
{
    if (tunTrafficTimer) tunTrafficTimer->stop();
}

// Trong vpn_client.cpp

void VPNClient::processTUNTraffic()
{
    if (!authenticated || !tun.isOpened()) return;

    char buffer[4096];
    int packetsRead = 0;

    while (packetsRead < 100) {
        int n = tun.readPacket(buffer, sizeof(buffer));
        if (n <= 0) break;

        // === LOGIC LỌC VÀ CHUẨN HÓA GÓI TIN ===
        char* sendData = buffer;
        int sendSize = n;
        bool shouldSend = false;

        uint8_t firstByte = (uint8_t)buffer[0];

        // TRƯỜNG HỢP 1: Raw IP Packet (IPv4 bắt đầu bằng 0x4...)
        // Một số driver TAP ở chế độ đặc biệt có thể trả về cái này
        if ((firstByte >> 4) == 4) {
            shouldSend = true;
        }
        // TRƯỜNG HỢP 2: Ethernet Frame (Thường gặp trên Windows TAP)
        // Header dài 14 bytes. Kiểm tra EtherType tại byte 12-13
        // 0x08 0x00 là IPv4
        else if (n > 14 && (uint8_t)buffer[12] == 0x08 && (uint8_t)buffer[13] == 0x00) {
            // Kiểm tra byte đầu tiên của phần Payload (byte thứ 14)
            uint8_t ipVer = (uint8_t)buffer[14] >> 4;
            if (ipVer == 4) {
                // Cắt bỏ 14 byte đầu (Ethernet Header)
                sendData = buffer + 14;
                sendSize = n - 14;
                shouldSend = true;
            }
        }

        // Chỉ gửi nếu là IPv4 hợp lệ
        if (shouldSend) {
            sendPacketToServer(QByteArray(sendData, sendSize));
            packetsRead++;
        }
        // Các gói ARP, IPv6, rác sẽ bị Drop tại đây -> Server sẽ hết lỗi Invalid Argument
    }

    static int statsCounter = 0;
    if (++statsCounter >= 100) {
        emit trafficStatsUpdated(totalBytesSent, totalBytesReceived);
        statsCounter = 0;
    }
}

void VPNClient::sendPacketToServer(const QByteArray& packetData)
{
    if (!authenticated || !cryptoReady || packetData.size() > 1500) return;

    QByteArray encryptedData;
    if (!encryptPacket(packetData, encryptedData)) {
        return;
    }

    // ✅ PRIORITY: Luôn dùng UDP nếu ready
    if (udpReady && udpSocket->state() == QAbstractSocket::BoundState) {
        int totalSize = 8 + encryptedData.size();
        QByteArray udpPacket(totalSize, 0);

        *(qint32*)udpPacket.data() = clientId;
        *(qint32*)(udpPacket.data() + 4) = encryptedData.size();
        memcpy(udpPacket.data() + 8, encryptedData.constData(), encryptedData.size());

        qint64 sent = udpSocket->writeDatagram(udpPacket, udpServerAddr, udpServerPort);

        if (sent > 0) {
            totalBytesSent += packetData.size();
        }
        return; // ✅ CRITICAL: RETURN ngay, không fallback TCP
    }

    // Chỉ log warning thay vì gửi qua TCP
    static int tcpFallbackCount = 0;
    if (++tcpFallbackCount % 100 == 0) {
        qWarning() << "[WARN] UDP not ready, dropped" << tcpFallbackCount << "packets";
    }
}

void VPNClient::onUdpReadyRead()
{
    int packetsProcessed = 0;

    while (udpSocket->hasPendingDatagrams() && packetsProcessed < 200) {
        QByteArray datagram;
        datagram.resize(udpSocket->pendingDatagramSize());

        QHostAddress sender;
        quint16 senderPort;
        qint64 size = udpSocket->readDatagram(datagram.data(), datagram.size(),
                                              &sender, &senderPort);

        if (size < 8) continue;

        qint32 recvClientId = *(qint32*)datagram.data();
        qint32 encryptedSize = *(qint32*)(datagram.data() + 4);

        // Handshake ACK
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

        // ✓ DECRYPT DATA PACKET
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
                    }
                } else {
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

void VPNClient::onReadyRead() {
    if (!tlsWrapper || !socket || socket->state() != QAbstractSocket::ConnectedState) {
        return;
    }

    char buffer[4096];
    int totalRead = 0;
    int maxReads = 10; // Giới hạn số lần đọc mỗi lần trigger

    for (int i = 0; i < maxReads; i++) {
        int bytesRead = tlsWrapper->recv(buffer, sizeof(buffer));

        if (bytesRead > 0) {
            totalRead += bytesRead;
            messageBuffer.append(QByteArray(buffer, bytesRead));

            int udpKeyPos = messageBuffer.indexOf("UDP_KEY|");
            if (udpKeyPos != -1) {
                int newlineAfterKey = messageBuffer.indexOf('\n', udpKeyPos);
                if (newlineAfterKey != -1) {
                    QByteArray keyLine = messageBuffer.mid(udpKeyPos, newlineAfterKey - udpKeyPos);
                    messageBuffer.remove(udpKeyPos, newlineAfterKey - udpKeyPos + 1);

                    if (keyLine.size() > 8) {
                        QByteArray b64Key = keyLine.mid(8);
                        QByteArray keyData = QByteArray::fromBase64(b64Key);

                        if (keyData.size() == 32) {
                            sharedKey.assign(keyData.begin(), keyData.end());
                            cryptoReady = true;
                            txCounter = 0;
                            rxCounter = 0;
                            qDebug() << "[CRYPTO] ✓ UDP encryption ready (Key received via Base64)";
                            setupUDPConnection();
                        } else {
                            qWarning() << "[CRYPTO] Invalid key size after Base64 decode:" << keyData.size();
                        }
                    }
                }
            }

            // Process text messages
            int newlinePos;
            while ((newlinePos = messageBuffer.indexOf('\n')) != -1) {
                QByteArray line = messageBuffer.left(newlinePos);
                messageBuffer.remove(0, newlinePos + 1);

                QString message = QString::fromUtf8(line).trimmed();
                if (message.startsWith("UDP_KEY|")) continue;

                parseServerMessage(message);
                emit messageReceived(message);
            }

            // ✅ CRITICAL: Nếu không còn data trong SSL buffer, thoát ngay
            if (SSL_pending(tlsWrapper->getSSL()) == 0) {
                break;
            }
        }
        else if (bytesRead == 0) {
            qDebug() << "[TLS] Server closed connection";
            socket->disconnectFromHost();
            break;
        }
        else { // bytesRead < 0
            int sslError = SSL_get_error(tlsWrapper->getSSL(), bytesRead);

            // ✅ WANT_READ/WANT_WRITE là bình thường với non-blocking socket
            if (sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE) {
                break; // Chờ event tiếp theo
            }

            // ✅ Log errors khác
            if (sslError != SSL_ERROR_ZERO_RETURN) {
                qWarning() << "[TLS] SSL Error:" << sslError;
            }
            break;
        }
    }

    // ✅ CRITICAL: Giới hạn buffer size để tránh memory leak
    if (messageBuffer.size() > 65536) {
        qWarning() << "[SECURITY] Message buffer overflow, clearing";
        messageBuffer.clear();
    }
}

void VPNClient::setupUDPConnection()
{
    qDebug() << "[SETUP] Starting UDP and TUN setup...";
    qDebug() << "[SETUP] cryptoReady:" << cryptoReady;
    qDebug() << "[SETUP] assignedVpnIP:" << assignedVpnIP;
    qDebug() << "[SETUP] udpServerPort:" << udpServerPort;

    // 1. Bind UDP socket
    if (udpSocket->state() != QAbstractSocket::BoundState) {
        if (udpSocket->bind(QHostAddress::AnyIPv4, 0)) {
            qDebug() << "[UDP] ✓ Bound to local port" << udpSocket->localPort();
        } else {
            qWarning() << "[UDP] ✗ Bind failed:" << udpSocket->errorString();
            emit error("UDP bind failed: " + udpSocket->errorString());
            return;
        }
    }

    // 2. Setup TUN interface FIRST (before UDP handshake)
    if (!tun.isOpened()) {
        qDebug() << "[TUN] Creating TAP adapter...";

        if (!tun.create()) {
            qWarning() << "[TUN] ✗ Failed to create TAP device";
            emit error("Failed to create TAP adapter. Please install TAP-Windows driver.");
            return;
        }

        qDebug() << "[TUN] ✓ TAP device created";

        // Configure TUN with assigned VPN IP
        QString serverIP = serverHost; // Use the server's hostname/IP
        qDebug() << "[TUN] Configuring: VPN_IP=" << assignedVpnIP
                 << " SERVER_IP=" << serverIP;

        if (!tun.configure(assignedVpnIP.toStdString(),
                           "255.255.255.0",
                           serverIP.toStdString())) {
            qWarning() << "[TUN] ✗ Configuration failed";
            emit error("Failed to configure TAP adapter");
            tun.close();
            return;
        }

        tun.setIPv6Status(false);

        qDebug() << "[TUN] ✓ Configured successfully";
        emit statusReceived("TUN interface configured with IP " + assignedVpnIP);
    } else {
        qDebug() << "[TUN] Already opened";
    }

    // 3. Start UDP handshake
    if (udpServerPort > 0 && !udpServerAddr.isNull()) {
        qDebug() << "[UDP] Starting handshake to" << udpServerAddr.toString() << ":" << udpServerPort;
        startUdpHandshake();
        QThread::msleep(500); // Give handshake time to complete
    } else {
        qWarning() << "[UDP] Invalid server address or port";
    }

    // 4. Start TUN traffic processing
    qDebug() << "[TRAFFIC] Starting TUN traffic processing...";
    startTUNTrafficGeneration();

    qDebug() << "[SETUP] ✓ VPN fully initialized";
    emit statusReceived("VPN connection established");
}

void VPNClient::parseServerMessage(const QString& message)
{
    qDebug() << "[PARSE]" << message;

    if (message.startsWith("AUTH_OK|")) {
        authenticated = true;
        //pingTimer->start();

        // Parse VPN_IP
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            assignedVpnIP = message.mid(start, end - start).trimmed();
            qDebug() << "[CONFIG] VPN IP:" << assignedVpnIP;
            emit vpnIPAssigned(assignedVpnIP);
        }

        // Parse UDP_PORT
        if (message.contains("UDP_PORT:")) {
            int start = message.indexOf("UDP_PORT:") + 9;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            udpServerPort = message.mid(start, end - start).trimmed().toUShort();
            udpServerAddr = QHostAddress(serverHost);
            qDebug() << "[CONFIG] UDP Port:" << udpServerPort;
        }

        // Parse CLIENT_ID
        if (message.contains("CLIENT_ID:")) {
            int start = message.indexOf("CLIENT_ID:") + 10;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            clientId = message.mid(start, end - start).trimmed().toInt();
            qDebug() << "[CONFIG] Client ID:" << clientId;
        }

        // ✅ Request UDP key (will be received in onConnected loop)
        qDebug() << "[CRYPTO] Requesting UDP key...";
        requestUDPKey();

        emit authenticationResult(true, "Authentication successful");
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
        qDebug() << "[PING] Received PONG";
    }
    // ✅ REMOVED: UDP_KEY handling (now in onConnected)
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
    if (!cryptoReady || sharedKey.empty() || !encryptCtx) return false;

    std::vector<uint8_t> iv(12);
    uint64_t counter = txCounter++;
    memcpy(iv.data(), &counter, 8);

    // Khởi tạo các vector và biến
    // Cấp phát đủ dung lượng (plain.size() + 16) để tránh lỗi
    std::vector<uint8_t> ciphertext(plain.size() + 16);
    std::vector<uint8_t> tag(16);
    int len = 0, cipherLen = 0;
    // --- KẾT THÚC PHẦN KHAI BÁO ---


    // --- PHẦN LOGIC (BẠN ĐÃ DÁN) ---
    // TÁI SỬ DỤNG context, chỉ cần Init lại với IV mới
    if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, sharedKey.data(), iv.data()) != 1) {
        return false;
    }

    // Mã hóa
    if (EVP_EncryptUpdate(encryptCtx, ciphertext.data(), &len,
                          (const uint8_t*)plain.constData(), plain.size()) != 1) {
        return false;
    }
    cipherLen = len;

    if (EVP_EncryptFinal_ex(encryptCtx, ciphertext.data() + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        return false;
    }

    // --- SỬA LỖI LOGIC TẠI ĐÂY ---
    cipherLen += len; // <-- Bước 1: Cộng thêm len từ EncryptFinal
    ciphertext.resize(cipherLen); // <-- Bước 2: Resize vector về kích thước thật
    // --- KẾT THÚC SỬA LỖI ---


    // Code copy vào QByteArray 'encrypted' giữ nguyên
    encrypted.resize(28 + ciphertext.size()); // <-- Bây giờ ciphertext.size() đã đúng
    memcpy(encrypted.data(), iv.data(), 12);
    memcpy(encrypted.data() + 12, tag.data(), 16);
    memcpy(encrypted.data() + 28, ciphertext.data(), ciphertext.size());

    return true;
}


bool VPNClient::decryptPacket(const QByteArray& encrypted, QByteArray& plain)
{
    // 1. Kiểm tra ban đầu (dùng decryptCtx và check size tối thiểu)
    if (!cryptoReady || sharedKey.empty() || !decryptCtx || encrypted.size() < 28) {
        return false;
    }

    // 2. Trích xuất con trỏ tới các phần của gói tin
    // Gói tin có cấu trúc: [IV: 12 bytes][Tag: 16 bytes][Ciphertext: N bytes]
    const uint8_t* iv_ptr = (const uint8_t*)encrypted.constData();
    const uint8_t* tag_ptr = (const uint8_t*)encrypted.constData() + 12;
    const uint8_t* ciphertext_ptr = (const uint8_t*)encrypted.constData() + 28;
    int ciphertext_len = encrypted.size() - 28;

    // 3. Chống tấn công Replay (Phát lại) - Dùng Cửa Sổ Trượt (Sliding Window)
    uint64_t nonce = 0;
    memcpy(&nonce, iv_ptr, 8); // Lấy 8 byte counter từ IV

    // Trường hợp 1: Gói tin mới (nonce cao nhất)
    if (nonce > rxCounter) {
        // "Trượt" (slide) cửa sổ
        uint64_t diff = nonce - rxCounter;
        if (diff < 64) {
            // Dịch (shift) bitmap sang trái 'diff' vị trí
            rxWindowBitmap <<= diff;
        } else {
            // Chênh lệch quá lớn, coi như reset cửa sổ
            rxWindowBitmap = 0;
        }

        // Đánh dấu bit cho gói tin mới này (bit 0)
        rxWindowBitmap |= 1;

        // Cập nhật counter cao nhất
        rxCounter = nonce;
    }
    // Trường hợp 2: Gói tin cũ (out-of-order) hoặc lặp lại (replay)
    else {
        uint64_t diff = rxCounter - nonce;

        // 2a. Gói tin quá cũ (nằm ngoài cửa sổ 64-bit)
        if (diff >= 64) {
            // qWarning() << "[SECURITY] Rejected (Too Old): nonce:" << nonce << "rxCounter:" << rxCounter;
            return false; // Quá cũ, từ chối
        }

        // 2b. Gói tin nằm trong cửa sổ, kiểm tra bit
        uint64_t bit = 1ULL << diff; // Dùng 1ULL để đảm bảo là 64-bit shift
        if ((rxWindowBitmap & bit) != 0) {
            // Bit đã được set -> Gói tin này đã được xử lý
            // qWarning() << "[SECURITY] Rejected (Replay): nonce:" << nonce << "rxCounter:" << rxCounter;
            return false; // Gói lặp lại, từ chối
        }

        // 2c. Gói tin hợp lệ (out-of-order), chưa xử lý
        // Đánh dấu bit này là "đã xử lý"
        rxWindowBitmap |= bit;

        // Chấp nhận gói tin và tiếp tục giải mã
    }

    // --- BẮT ĐẦU CODE GIẢI MÃ ---
    // Chuẩn bị buffer cho plaintext (kích thước tối đa bằng ciphertext)
    plain.resize(ciphertext_len + 16); // Thêm 16 byte đề phòng
    int len = 0, plainLen = 0;

    // 4. TÁI SỬ DỤNG context, Init lại với IV mới
    if (EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(decryptCtx, nullptr, nullptr, sharedKey.data(), iv_ptr) != 1) {
        return false;
    }

    // 5. Giải mã
    if (EVP_DecryptUpdate(decryptCtx, (uint8_t*)plain.data(), &len,
                          ciphertext_ptr, ciphertext_len) != 1) {
        return false;
    }
    plainLen = len;

    // 6. CRITICAL: Cung cấp Tag (lấy từ gói tin) để OpenSSL xác thực
    if (EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_ptr) != 1) {
        return false;
    }

    // 7. Hoàn tất (Finalize). Hàm này sẽ thất bại (return <= 0) nếu Tag không khớp!
    int ret = EVP_DecryptFinal_ex(decryptCtx, (uint8_t*)plain.data() + len, &len);

    if (ret <= 0) {
        // qWarning() << "[CRYPTO] Decrypt failed: Tag mismatch or corrupted packet.";
        plain.clear(); // Xóa dữ liệu rác
        return false; // Xác thực thất bại!
    }
    // --- KẾT THÚC CODE GIẢI MÃ ---

    // 8. Resize QByteArray 'plain' về kích thước thật
    plainLen += len;
    plain.resize(plainLen);

    return true;
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
