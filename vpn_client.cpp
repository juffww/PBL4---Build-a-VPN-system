#include <QRandomGenerator>
#include <QDateTime>
#include "vpn_client.h"
#include <QHostAddress>
#include <QDebug>
#include <QThread>
#include <cstring>
#include <QRegularExpression>
#include <queue>
#include <chrono>
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
    udpHandshakeTimer(nullptr),
    networkManager(nullptr), totalBytesReceived(0),
    totalBytesSent(0), tlsWrapper(nullptr),
    pendingPacketSize(0), isReadingPacketData(false), cryptoReady(false),
    txCounter(0), rxCounter(0), rxWindowBitmap(0)
{
    socket = new QTcpSocket(this);
    udpSocket = new QUdpSocket(this);

    int bufferSize = 8 * 1024 * 1024;
    udpSocket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, bufferSize);
    udpSocket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, bufferSize);
    socket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, bufferSize);
    socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, bufferSize);

    pingTimer = new QTimer(this);
    networkManager = new QNetworkAccessManager(this);

    tlsReadPoller = new QTimer(this);
    tlsReadPoller->setInterval(10);

    cryptoBuffer.resize(65536);
    udpSendBuffer.resize(65536);

    encryptCtx = EVP_CIPHER_CTX_new();
    decryptCtx = EVP_CIPHER_CTX_new();

    if (!encryptCtx || !decryptCtx) {
        qWarning() << "[CRYPTO] Failed to create EVP contexts";
    }

    if (encryptCtx) {
        EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    }

    if (decryptCtx) {
        EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    }


    connect(tlsReadPoller, &QTimer::timeout, this, &VPNClient::onReadyRead);

    connect(socket, &QTcpSocket::connected, this, &VPNClient::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &VPNClient::onDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);
    connect(socket, &QAbstractSocket::errorOccurred, this, &VPNClient::onError);
    connect(udpSocket, &QUdpSocket::readyRead, this, &VPNClient::onUdpReadyRead);

    pingTimer->setInterval(30000);
}

VPNClient::~VPNClient()
{
    disconnectFromServer();
    if (tlsWrapper) {
        tlsWrapper->cleanup();
        delete tlsWrapper;
        tlsWrapper = nullptr;
    }

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
    udpReady = false;

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
                    int newlinePos = messageBuffer.indexOf('\n', udpKeyPos);

                    if (newlinePos != -1) {
                        QByteArray keyLine = messageBuffer.mid(udpKeyPos, newlinePos - udpKeyPos);

                        qDebug() << "[CRYPTO] Found UDP_KEY line:" << keyLine;

                        messageBuffer.remove(udpKeyPos, newlinePos - udpKeyPos + 1);

                        if (keyLine.size() > 8) {
                            QByteArray b64Key = keyLine.mid(8);

                            QByteArray keyData = QByteArray::fromBase64(b64Key);

                            if (keyData.size() == 32) {
                                sharedKey.assign(keyData.begin(), keyData.end());
                                cryptoReady = true;
                                txCounter = 0;
                                rxCounter = 0;
                                rxWindowBitmap = 0;

                                qDebug() << "[CRYPTO] ✓ UDP encryption ready (Base64 decoded)";
                                keyReceived = true;
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

    connect(socket, &QTcpSocket::readyRead, this, &VPNClient::onReadyRead);

    qDebug() << "[TLS] ✓ Connection fully established";
}

void VPNClient::disconnectFromServer()
{
    pingTimer->stop();
    if (tlsReadPoller) tlsReadPoller->stop();

    stopTUNTrafficGeneration();

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

    if (socket->state() != QAbstractSocket::UnconnectedState) {
        sendMessage("DISCONNECT");
        socket->disconnectFromHost();
        if (socket->state() != QAbstractSocket::UnconnectedState) {
            socket->waitForDisconnected(1000); // Giảm xuống 1000ms cho nhanh
        }
    }

    qDebug() << "[CLIENT] Disconnected completely.";
}

bool VPNClient::isConnected() const
{
    return socket->state() == QAbstractSocket::ConnectedState && authenticated;
}

void VPNClient::startTUNTrafficGeneration() {
    if (authenticated && !tunThreadRunning) {
        tunThreadRunning = true;
        tunThread = std::thread(&VPNClient::tunWorker, this);
    }
}

void VPNClient::stopTUNTrafficGeneration() {
    tunThreadRunning = false;
    if (tunThread.joinable()) {
        tunThread.join();
    }
}

void VPNClient::tunWorker() {
    char readBuffer[4096];
    HANDLE waitEvent = tun.getReadWaitEvent();

    qDebug() << "[WORKER] Started high-performance data plane";

    int debugCount = 0;

    while (tunThreadRunning && tun.isOpened()) {
        DWORD waitResult = WaitForSingleObject(waitEvent, 100);

        if (waitResult == WAIT_OBJECT_0) {
            while (true) {
                int n = tun.readPacket(readBuffer, sizeof(readBuffer));
                if (n <= 0) break;

                if (debugCount < 10) {
                    //qDebug() << "[WORKER] Read" << n << "bytes from TUN. Encrypting...";
                }

                if (!authenticated || !cryptoReady) continue;

                int plainSize = n;
                int maxEncryptedSize = plainSize + 28;

                if (udpSendBuffer.size() < (8 + maxEncryptedSize)) {
                    udpSendBuffer.resize(8 + maxEncryptedSize);
                }

                uint8_t* sendPtr = udpSendBuffer.data();

                std::vector<uint8_t> iv(12);
                uint64_t counter = txCounter++;
                memcpy(iv.data(), &counter, 8);

                int len = 0;
                int cipherLen = 0;

                // **SỬA LẠI HOÀN TOÀN - KHỞI TẠO ĐÚNG:**
                // Reset về trạng thái ban đầu
                if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                    qWarning() << "[WORKER] Reset cipher failed!";
                    continue;
                }

                // Set IV length
                if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
                    qWarning() << "[WORKER] Set IV length failed!";
                    continue;
                }

                // Set key và IV
                if (EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, sharedKey.data(), iv.data()) != 1) {
                    qWarning() << "[WORKER] Set key/IV failed!";
                    continue;
                }

                uint8_t* destCipher = sendPtr + 36;

                if (EVP_EncryptUpdate(encryptCtx, destCipher, &len, (const uint8_t*)readBuffer, plainSize) != 1) {
                    qWarning() << "[WORKER] Encrypt Update Failed!";
                    continue;
                }
                cipherLen = len;

                if (EVP_EncryptFinal_ex(encryptCtx, destCipher + len, &len) != 1) {
                    qWarning() << "[WORKER] Encrypt Final Failed!";
                    continue;
                }
                cipherLen += len;

                uint8_t tag[16];
                if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
                    qWarning() << "[WORKER] Get TAG Failed!";
                    continue;
                }

                *(qint32*)sendPtr = clientId;
                qint32 payloadSize = 12 + 16 + cipherLen;
                *(qint32*)(sendPtr + 4) = payloadSize;
                memcpy(sendPtr + 8, iv.data(), 12);
                memcpy(sendPtr + 20, tag, 16);

                int totalPacketSize = 8 + payloadSize;

                int sent = sendto(nativeUdpSocket,
                                  (const char*)sendPtr,
                                  totalPacketSize,
                                  0,
                                  (struct sockaddr*)&nativeServerAddr,
                                  sizeof(nativeServerAddr));

                // if (sent > 0) {
                //     totalBytesSent += n;
                //     if (debugCount < 10) {
                //         qDebug() << "[WORKER] ✓ Sent" << sent << "bytes via UDP to Server";
                //         debugCount++;
                //     }
                // } else {
                //     int err = WSAGetLastError();
                //     qWarning() << "[WORKER] UDP Send failed. Error code:" << err;
                // }
            }
        }
    }
}
// void VPNClient::tunWorker() {
//     char readBuffer[4096];
//     HANDLE waitEvent = tun.getReadWaitEvent();

//     qDebug() << "[WORKER] Started high-performance data plane";

//     int debugCount = 0;

//     // **THÊM: Error handling & Rate limiting**
//     int consecutiveErrors = 0;
//     const int MAX_CONSECUTIVE_ERRORS = 10;
//     int packetsSentThisSecond = 0;
//     auto lastSecond = std::chrono::steady_clock::now();
//     const int MAX_PACKETS_PER_SECOND = 3000; // Giới hạn 3000 pps

//     // **THÊM: Pending queue**
//     std::queue<std::vector<uint8_t>> pendingQueue;
//     const size_t MAX_PENDING = 50;
//     int totalDropped = 0;

//     while (tunThreadRunning && tun.isOpened()) {
//         // **1. XỬ LÝ PENDING QUEUE TRƯỚC (quan trọng!)**
//         while (!pendingQueue.empty()) {
//             auto& packet = pendingQueue.front();

//             int sent = sendto(nativeUdpSocket,
//                               (const char*)packet.data(),
//                               packet.size(),
//                               0,
//                               (struct sockaddr*)&nativeServerAddr,
//                               sizeof(nativeServerAddr));

//             if (sent > 0) {
//                 pendingQueue.pop();
//                 consecutiveErrors = 0;
//             } else {
//                 int err = WSAGetLastError();
//                 if (err == WSAEWOULDBLOCK) {
//                     // Vẫn đầy, chờ
//                     Sleep(2);
//                     break;
//                 } else {
//                     // Lỗi khác, drop packet
//                     pendingQueue.pop();
//                     totalDropped++;
//                 }
//             }
//         }

//         // **2. RATE LIMITING**
//         auto now = std::chrono::steady_clock::now();
//         auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastSecond);
//         if (elapsed.count() >= 1) {
//             if (packetsSentThisSecond > 2000 && debugCount < 5) {
//                 qDebug() << "[WORKER] Sent" << packetsSentThisSecond
//                          << "pps, Pending:" << pendingQueue.size()
//                          << ", Dropped:" << totalDropped;
//                 debugCount++;
//             }
//             packetsSentThisSecond = 0;
//             lastSecond = now;
//             totalDropped = 0;
//         }

//         // **3. ĐỌC VÀ MÃ HÓA PACKETS**
//         DWORD waitResult = WaitForSingleObject(waitEvent, 20); // Giảm từ 100ms → 20ms

//         if (waitResult == WAIT_OBJECT_0) {
//             int burstCount = 0;
//             const int MAX_BURST = 10; // Chỉ xử lý 10 packets mỗi burst

//             while (burstCount < MAX_BURST) {
//                 // Rate limiting check
//                 if (packetsSentThisSecond >= MAX_PACKETS_PER_SECOND) {
//                     Sleep(5);
//                     break;
//                 }

//                 int n = tun.readPacket(readBuffer, sizeof(readBuffer));
//                 if (n <= 0) break;

//                 if (!authenticated || !cryptoReady) continue;

//                 // **MÃ HÓA**
//                 int plainSize = n;
//                 int maxEncryptedSize = plainSize + 28;

//                 if (udpSendBuffer.size() < (8 + maxEncryptedSize)) {
//                     udpSendBuffer.resize(8 + maxEncryptedSize);
//                 }

//                 uint8_t* sendPtr = udpSendBuffer.data();

//                 std::vector<uint8_t> iv(12);
//                 uint64_t counter = txCounter++;
//                 memcpy(iv.data(), &counter, 8);

//                 int len = 0;
//                 int cipherLen = 0;

//                 if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
//                     qWarning() << "[WORKER] Reset cipher failed!";
//                     continue;
//                 }

//                 if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
//                     qWarning() << "[WORKER] Set IV length failed!";
//                     continue;
//                 }

//                 if (EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, sharedKey.data(), iv.data()) != 1) {
//                     qWarning() << "[WORKER] Set key/IV failed!";
//                     continue;
//                 }

//                 uint8_t* destCipher = sendPtr + 36;

//                 if (EVP_EncryptUpdate(encryptCtx, destCipher, &len, (const uint8_t*)readBuffer, plainSize) != 1) {
//                     qWarning() << "[WORKER] Encrypt Update Failed!";
//                     continue;
//                 }
//                 cipherLen = len;

//                 if (EVP_EncryptFinal_ex(encryptCtx, destCipher + len, &len) != 1) {
//                     qWarning() << "[WORKER] Encrypt Final Failed!";
//                     continue;
//                 }
//                 cipherLen += len;

//                 uint8_t tag[16];
//                 if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
//                     qWarning() << "[WORKER] Get TAG Failed!";
//                     continue;
//                 }

//                 // **ĐÓNG GÓI**
//                 *(qint32*)sendPtr = clientId;
//                 qint32 payloadSize = 12 + 16 + cipherLen;
//                 *(qint32*)(sendPtr + 4) = payloadSize;
//                 memcpy(sendPtr + 8, iv.data(), 12);
//                 memcpy(sendPtr + 20, tag, 16);

//                 int totalPacketSize = 8 + payloadSize;

//                 // **4. GỬI VỚI ERROR HANDLING**
//                 int sent = sendto(nativeUdpSocket,
//                                   (const char*)sendPtr,
//                                   totalPacketSize,
//                                   0,
//                                   (struct sockaddr*)&nativeServerAddr,
//                                   sizeof(nativeServerAddr));

//                 if (sent > 0) {
//                     totalBytesSent += n;
//                     packetsSentThisSecond++;
//                     consecutiveErrors = 0;
//                     burstCount++;
//                 } else {
//                     int err = WSAGetLastError();

//                     if (err == WSAEWOULDBLOCK) {
//                         // **BUFFER ĐẦY - ADD VÀO QUEUE**
//                         if (pendingQueue.size() < MAX_PENDING) {
//                             std::vector<uint8_t> packet(sendPtr, sendPtr + totalPacketSize);
//                             pendingQueue.push(packet);
//                         } else {
//                             // Queue đầy - drop packet
//                             totalDropped++;
//                             if (totalDropped % 100 == 0) {
//                                 qWarning() << "[WORKER] Dropped" << totalDropped
//                                            << "packets (queue overflow)";
//                             }
//                         }

//                         consecutiveErrors++;
//                         if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
//                             qWarning() << "[WORKER] Too many errors, backing off...";
//                             Sleep(10);
//                             consecutiveErrors = 0;
//                             break; // Break để xử lý pending queue
//                         }
//                     } else {
//                         // Lỗi fatal
//                         qWarning() << "[WORKER] Fatal UDP error:" << err;
//                         consecutiveErrors++;
//                     }
//                 }
//             } // end while burst
//         }
//     } // end while main loop

//     qDebug() << "[WORKER] Stopped. Pending:" << pendingQueue.size();
// }

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
    int maxReads = 10;

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

            int newlinePos;
            while ((newlinePos = messageBuffer.indexOf('\n')) != -1) {
                QByteArray line = messageBuffer.left(newlinePos);
                messageBuffer.remove(0, newlinePos + 1);

                QString message = QString::fromUtf8(line).trimmed();
                if (message.startsWith("UDP_KEY|")) continue;

                parseServerMessage(message);
                emit messageReceived(message);
            }

            if (SSL_pending(tlsWrapper->getSSL()) == 0) {
                break;
            }
        }
        else if (bytesRead == 0) {
            qDebug() << "[TLS] Server closed connection";
            socket->disconnectFromHost();
            break;
        }
        else {
            int sslError = SSL_get_error(tlsWrapper->getSSL(), bytesRead);

            if (sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE) {
                break;
            }

            if (sslError != SSL_ERROR_ZERO_RETURN) {
                qWarning() << "[TLS] SSL Error:" << sslError;
            }
            break;
        }
    }

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

    if (udpSocket->state() != QAbstractSocket::BoundState) {
        if (udpSocket->bind(QHostAddress::AnyIPv4, 0)) {
            qDebug() << "[UDP] ✓ Bound to local port" << udpSocket->localPort();
        } else {
            qWarning() << "[UDP] ✗ Bind failed:" << udpSocket->errorString();
            emit error("UDP bind failed: " + udpSocket->errorString());
            return;
        }
    }

    nativeUdpSocket = udpSocket->socketDescriptor();
    if (nativeUdpSocket == INVALID_SOCKET) {
        qWarning() << "[UDP] Failed to get native socket descriptor";
        return;
    }

    // // **THÊM: SET NATIVE SOCKET OPTIONS**
    // int sendBufSize = 8 * 1024 * 1024;
    // int recvBufSize = 8 * 1024 * 1024;

    // if (setsockopt(nativeUdpSocket, SOL_SOCKET, SO_SNDBUF,
    //                (const char*)&sendBufSize, sizeof(sendBufSize)) < 0) {
    //     qWarning() << "[UDP] Failed to set SO_SNDBUF:" << WSAGetLastError();
    // } else {
    //     qDebug() << "[UDP] ✓ Send buffer set to 8MB";
    // }

    // if (setsockopt(nativeUdpSocket, SOL_SOCKET, SO_RCVBUF,
    //                (const char*)&recvBufSize, sizeof(recvBufSize)) < 0) {
    //     qWarning() << "[UDP] Failed to set SO_RCVBUF:" << WSAGetLastError();
    // } else {
    //     qDebug() << "[UDP] ✓ Recv buffer set to 8MB";
    // }

    // // **VERIFY**
    // int actualSend = 0, actualRecv = 0;
    // int optLen = sizeof(int);
    // getsockopt(nativeUdpSocket, SOL_SOCKET, SO_SNDBUF, (char*)&actualSend, &optLen);
    // getsockopt(nativeUdpSocket, SOL_SOCKET, SO_RCVBUF, (char*)&actualRecv, &optLen);
    // qDebug() << "[UDP] Actual buffers - Send:" << actualSend << "Recv:" << actualRecv;

    memset(&nativeServerAddr, 0, sizeof(nativeServerAddr));
    nativeServerAddr.sin_family = AF_INET;
    nativeServerAddr.sin_port = htons(udpServerPort);

    std::string ipStr = udpServerAddr.toString().toStdString();
    if (inet_pton(AF_INET, ipStr.c_str(), &nativeServerAddr.sin_addr) <= 0) {
        qWarning() << "[UDP] Invalid server IP for native socket";
    }

    if (!tun.isOpened()) {
        qDebug() << "[TUN] Creating TAP adapter...";

        if (!tun.create()) {
            qWarning() << "[TUN] ✗ Failed to create TAP device";
            emit error("Failed to create TAP adapter. Please install TAP-Windows driver.");
            return;
        }

        qDebug() << "[TUN] ✓ TAP device created";

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

    if (udpServerPort > 0 && !udpServerAddr.isNull()) {
        qDebug() << "[UDP] Starting handshake to" << udpServerAddr.toString() << ":" << udpServerPort;
        startUdpHandshake();
        QThread::msleep(500); // Give handshake time to complete
    } else {
        qWarning() << "[UDP] Invalid server address or port";
    }

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

        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            assignedVpnIP = message.mid(start, end - start).trimmed();
            qDebug() << "[CONFIG] VPN IP:" << assignedVpnIP;
            emit vpnIPAssigned(assignedVpnIP);
        }

        if (message.contains("UDP_PORT:")) {
            int start = message.indexOf("UDP_PORT:") + 9;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            udpServerPort = message.mid(start, end - start).trimmed().toUShort();
            udpServerAddr = QHostAddress(serverHost);
            qDebug() << "[CONFIG] UDP Port:" << udpServerPort;
        }

        if (message.contains("CLIENT_ID:")) {
            int start = message.indexOf("CLIENT_ID:") + 10;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();
            clientId = message.mid(start, end - start).trimmed().toInt();
            qDebug() << "[CONFIG] Client ID:" << clientId;
        }

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
    // Kiểm tra điều kiện
    if (!cryptoReady || sharedKey.empty() || !encryptCtx) return false;

    // TỐI ƯU 1: Dùng mảng stack cho IV (nhanh hơn std::vector)
    uint8_t iv[12];
    uint64_t counter = txCounter++;
    memcpy(iv, &counter, 8);
    memset(iv + 8, 0, 4); // 4 byte cuối set bằng 0

    int len = 0, cipherLen = 0;
    int plainSize = plain.size();

    // Đảm bảo buffer thành viên đã được resize đủ dùng (chỉ làm 1 lần lúc khởi tạo)
    if (tagBuffer.size() != 16) tagBuffer.resize(16);
    // cryptoBuffer đã resize ở constructor (64KB) nên không cần check lại

    // 1. Init Context
    // Reset context (nullptr) nhanh hơn tạo mới
    if (EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, sharedKey.data(), iv) != 1) {
        return false;
    }

    // 2. Encrypt (Ghi thẳng vào cryptoBuffer - buffer tái sử dụng)
    if (EVP_EncryptUpdate(encryptCtx, cryptoBuffer.data(), &len,
                          (const uint8_t*)plain.constData(), plainSize) != 1) return false;
    cipherLen = len;

    // 3. Finalize
    if (EVP_EncryptFinal_ex(encryptCtx, cryptoBuffer.data() + len, &len) != 1) return false;
    cipherLen += len;

    // 4. Get Tag (Ghi vào tagBuffer thành viên)
    if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_GET_TAG, 16, tagBuffer.data()) != 1) return false;

    // 5. Đóng gói kết quả vào QByteArray đầu ra
    // Cấu trúc: [IV 12 bytes][Tag 16 bytes][Ciphertext]
    encrypted.resize(28 + cipherLen);

    // Copy IV
    memcpy(encrypted.data(), iv, 12);
    // Copy Tag (Sửa lỗi: dùng tagBuffer thay vì tag)
    memcpy(encrypted.data() + 12, tagBuffer.data(), 16);
    // Copy Ciphertext
    memcpy(encrypted.data() + 28, cryptoBuffer.data(), cipherLen);

    return true;
}

bool VPNClient::decryptPacket(const QByteArray& encrypted, QByteArray& plain)
{
    // Kiểm tra độ dài tối thiểu (Header 28 bytes: 12 IV + 16 Tag)
    if (!cryptoReady || sharedKey.empty() || !decryptCtx || encrypted.size() < 28) {
        return false;
    }

    // TỐI ƯU 2: Dùng con trỏ trực tiếp (Zero-copy), không tạo std::vector phụ
    const uint8_t* iv_ptr = (const uint8_t*)encrypted.constData();
    const uint8_t* tag_ptr = (const uint8_t*)encrypted.constData() + 12;
    const uint8_t* ciphertext_ptr = (const uint8_t*)encrypted.constData() + 28;
    int ciphertext_len = encrypted.size() - 28;

    // --- Logic chống tấn công phát lại (Anti-Replay) ---
    uint64_t nonce = 0;
    memcpy(&nonce, iv_ptr, 8);

    if (nonce > rxCounter) {
        uint64_t diff = nonce - rxCounter;
        if (diff < 64) {
            rxWindowBitmap <<= diff;
        } else {
            rxWindowBitmap = 0;
        }
        rxWindowBitmap |= 1;
        rxCounter = nonce;
    }
    else {
        uint64_t diff = rxCounter - nonce;
        if (diff >= 64) return false; // Gói tin quá cũ
        uint64_t bit = 1ULL << diff;
        if ((rxWindowBitmap & bit) != 0) return false; // Gói tin đã nhận rồi (Replay)
        rxWindowBitmap |= bit;
    }
    // ---------------------------------------------------

    // Resize buffer đầu ra
    plain.resize(ciphertext_len + 16); // +16 dự phòng padding (dù GCM ko cần nhưng an toàn)
    int len = 0, plainLen = 0;

    // 1. Init Decrypt
    if (EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(decryptCtx, nullptr, nullptr, sharedKey.data(), iv_ptr) != 1) {
        return false;
    }

    // 2. Update (Giải mã thẳng từ con trỏ ciphertext_ptr)
    if (EVP_DecryptUpdate(decryptCtx, (uint8_t*)plain.data(), &len,
                          ciphertext_ptr, ciphertext_len) != 1) {
        return false;
    }
    plainLen = len;

    // 3. Set Tag (Kiểm tra tính toàn vẹn)
    if (EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_ptr) != 1) {
        return false;
    }

    // 4. Finalize
    int ret = EVP_DecryptFinal_ex(decryptCtx, (uint8_t*)plain.data() + len, &len);

    if (ret <= 0) {
        plain.clear();
        // std::cerr << "Decryption failed (Bad Tag)\n"; // Uncomment để debug nếu cần
        return false;
    }

    plainLen += len;
    plain.resize(plainLen); // Resize về kích thước thật

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
}

void VPNClient::requestVPNIP()
{
    if (authenticated) sendMessage("GET_IP");
}

void VPNClient::requestStatus()
{
    if (authenticated) sendMessage("STATUS");
}

void VPNClient::shutdown()
{
    tun.shutdown();
}
