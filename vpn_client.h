#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <QObject>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QTimer>
#include <QString>
#include <QNetworkAccessManager>
#include <vector>
#include <atomic>
#include <mutex>
#include <openssl/evp.h>
#include "tun_interface.h"
#include "tls_wrapper_client.h"

class VPNClient : public QObject
{
    Q_OBJECT

public:
    explicit VPNClient(QObject *parent = nullptr);
    ~VPNClient();

    void connectToServer(const QString& host, int port);
    void disconnectFromServer();
    bool isConnected() const;

    void requestVPNIP();
    void requestStatus();
    QString getCurrentVPNIP() const { return assignedVpnIP; }

    // --- [THAY ĐỔI] Các hàm lấy thông số thống kê ---
    quint64 getBytesReceived() const;
    quint64 getBytesSent() const;
    void sendPing();           // Hàm gửi Ping
    double getPacketLoss();    // Hàm tính Packet Loss

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
    void processTUNTraffic();
    void requestUDPKey();

private:
    void authenticate();
    void sendMessage(const QString& message);
    void parseServerMessage(const QString& message);
    // void cleanupInternalState(); // Hàm này không thấy trong .cpp, có thể bỏ hoặc comment

    void sendPacketToServer(const QByteArray& packetData);
    void writePacketToTUN(const QByteArray& packetData);

    bool encryptPacket(const QByteArray& plain, QByteArray& encrypted);
    bool decryptPacket(const QByteArray& encrypted, QByteArray& plain);
    void setupUDPConnection();
    void setupRawUDPKey(const QByteArray& keyData);

    // --- [THAY ĐỔI] Biến theo dõi Ping ---
    qint64 m_pingSentTime;
    // -------------------------------------

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

    QTimer* tunTrafficTimer;
    QNetworkAccessManager* networkManager;

    // --- [THAY ĐỔI] Biến thống kê Bytes ---
    quint64 totalBytesReceived;
    quint64 totalBytesSent;
    // --------------------------------------

    TLSWrapper* tlsWrapper;
    QByteArray messageBuffer;

    TUNInterface tun;

    int pendingPacketSize;
    bool isReadingPacketData;
    QByteArray pendingPacketData;

    std::atomic<uint64_t> txCounter{0};
    std::atomic<uint64_t> rxCounter{0};
    std::atomic<uint64_t> rxWindowBitmap{0};

    std::mutex encryptMutex;
    std::mutex decryptMutex;

    EVP_CIPHER_CTX* encryptCtx;
    EVP_CIPHER_CTX* decryptCtx;
    std::vector<uint8_t> sharedKey;
    bool cryptoReady;

    // --- [THAY ĐỔI] Biến thống kê Packet Loss ---
    quint64 totalPacketsReceived;
    quint64 totalDecryptErrors;
    // --------------------------------------------
};

#endif
