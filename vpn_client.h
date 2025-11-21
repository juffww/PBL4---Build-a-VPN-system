#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <QObject>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QTimer>
#include <QString>
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

    void connectToServer(const QString& host, int port, const QString& username, const QString& password);
    void disconnectFromServer();
    bool isConnected() const;

    void requestVPNIP();
    void requestStatus();
    QString getCurrentVPNIP() const { return assignedVpnIP; }
    quint64 getBytesReceived() const;
    quint64 getBytesSent() const;

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

private slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();
    void onUdpReadyRead();
    void sendUdpHandshake();
    void startUdpHandshake();
    void onError(QAbstractSocket::SocketError socketError);
    // void sendPing();
    void processTUNTraffic();
    void requestUDPKey();

private:
    void authenticate(const QString& username, const QString& password);
    void sendMessage(const QString& message);
    void parseServerMessage(const QString& message);

    void sendPacketToServer(const QByteArray& packetData);
    void writePacketToTUN(const QByteArray& packetData);

    bool encryptPacket(const QByteArray& plain, QByteArray& encrypted);
    bool decryptPacket(const QByteArray& encrypted, QByteArray& plain);
    void setupUDPConnection();

    // TCP
    QTcpSocket *socket;
    QTimer *pingTimer;
    QTimer *tlsReadPoller;

    // UDP - THÊM
    QUdpSocket *udpSocket;
    QHostAddress udpServerAddr;
    quint16 udpServerPort;
    bool udpReady;

    bool authenticated;
    QString serverHost;
    int serverPort;
    QString assignedVpnIP;
    QString serverIP;
    int clientId;  // THÊM: để đóng gói UDP
    QTimer *udpHandshakeTimer;

    QTimer* tunTrafficTimer;
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
    uint64_t txCounter;  // Nonce counter for encryption
    uint64_t rxCounter;  // Track received nonces for replay protection
    uint64_t rxWindowBitmap;
};

#endif
