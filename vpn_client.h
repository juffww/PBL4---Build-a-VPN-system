#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <QObject>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QTimer>
#include <QString>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <atomic>
#include <QNetworkAccessManager>
#include <openssl/evp.h>
#include "tun_interface.h"
#include "tls_wrapper_client.h"

class VPNClient : public QObject
{
    Q_OBJECT

public:
    explicit VPNClient(QObject *parent = nullptr);
    ~VPNClient();

    void shutdown();
    void connectToServer(const QString& host, int port);
    void disconnectFromServer();
    bool isConnected() const;

    void requestVPNIP();
    void requestStatus();
    QString getCurrentVPNIP() const { return assignedVpnIP; }
    quint64 getBytesReceived() const;
    quint64 getBytesSent() const;

    void sendPing();
    double getPacketLoss();

public slots:
    void startTUNTrafficGeneration();
    void stopTUNTrafficGeneration();
    void simulateWebBrowsing();

signals:
    void connected();
    void disconnected();
    void error(const QString& errorMessage);
    void authenticationResult(bool success, const QString& message);
    void messageReceived(const QString& message);
    void vpnIPAssigned(const QString& vpnIP);
    void statusReceived(const QString& status);
    void trafficStatsUpdated(quint64 bytesSent, quint64 bytesReceived);

    void pingUpdated(int ms);

private slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();
    void onUdpReadyRead();
    void sendUdpHandshake();
    void startUdpHandshake();
    void onError(QAbstractSocket::SocketError socketError);
    void requestUDPKey();

private:
    void authenticate();
    void sendMessage(const QString& message);
    void parseServerMessage(const QString& message);

    void writePacketToTUN(const QByteArray& packetData);

    bool encryptPacket(const QByteArray& plain, QByteArray& encrypted);
    bool decryptPacket(const QByteArray& encrypted, QByteArray& plain);
    void setupUDPConnection();

    void tunWorker();

    SOCKET nativeUdpSocket = INVALID_SOCKET;
    struct sockaddr_in nativeServerAddr;

    std::vector<uint8_t> cryptoBuffer;
    std::vector<uint8_t> tagBuffer;
    std::vector<uint8_t> udpSendBuffer;

    QTcpSocket *socket;
    QTimer *pingTimer;
    QTimer *tlsReadPoller;

    QUdpSocket *udpSocket;
    QHostAddress udpServerAddr;
    quint16 udpServerPort;
    bool udpReady;

    bool authenticated;
    QString serverHost;
    int serverPort;
    QString assignedVpnIP;
    QString serverIP;
    int clientId;
    QTimer *udpHandshakeTimer;

    std::thread tunThread;
    std::atomic<bool> tunThreadRunning;
    QNetworkAccessManager* networkManager;
    quint64 totalBytesReceived;
    quint64 totalBytesSent;

    TLSWrapper* tlsWrapper;

    QByteArray messageBuffer;

    TUNInterface tun;

    int pendingPacketSize;
    bool isReadingPacketData;
    QByteArray pendingPacketData;

    EVP_CIPHER_CTX *encryptCtx;
    EVP_CIPHER_CTX *decryptCtx;
    bool cryptoReady;
    std::vector<uint8_t> sharedKey;
    uint64_t txCounter;
    uint64_t rxCounter;
    uint64_t rxWindowBitmap;

    qint64 m_pingSentTime;
    quint64 totalPacketsReceived;
    quint64 totalDecryptErrors;
};

#endif
