#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <QString>
#include <QNetworkAccessManager>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "tun_interface.h"

class VPNClient : public QObject
{
    Q_OBJECT

public:
    explicit VPNClient(QObject *parent = nullptr);
    ~VPNClient();

    void connectToServer(const QString& host, int port, const QString& username, const QString& password);
    void disconnectFromServer();
    bool isConnected() const;

    // VPN specific methods
    void requestVPNIP();
    void requestStatus();
    QString getCurrentVPNIP() const { return assignedVpnIP; }
    quint64 getBytesReceived() const;
    quint64 getBytesSent() const;

public slots:
    // TUN traffic simulation
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
    void onError(QAbstractSocket::SocketError socketError);
    void sendPing();
    void processTUNTraffic();  // Renamed from generateTUNTraffic

private:
    // Authentication and communication
    void authenticate(const QString& username, const QString& password);
    void sendMessage(const QString& message);
    void parseServerMessage(const QString& message);

    // NEW: Packet handling functions
    void sendPacketToServer(const QByteArray& packetData);
    void writePacketToTUN(const QByteArray& packetData);

    // Helper methods để xử lý message validation
    bool isValidTextMessage(const QString& message);
    bool isValidPacketData(const QString& packetData);

    // Socket and connection
    QTcpSocket *socket;
    QTimer *pingTimer;

    // Authentication and server info
    bool authenticated;
    QString serverHost;
    int serverPort;
    QString assignedVpnIP;
    QString serverIP;

    // Protocol verification
    bool serverProtocolVerified;
    QString expectedServerProtocol;

    // Traffic simulation
    QTimer* tunTrafficTimer;
    QNetworkAccessManager* networkManager;
    quint64 totalBytesReceived;
    quint64 totalBytesSent;

    // TUN interface and packet handling
    TUNInterface tun;
    QByteArray tunReadBuffer;

    // NEW: Packet data state management
    int pendingPacketSize;
    bool isReadingPacketData;
    QByteArray pendingPacketData;
};

#endif // VPN_CLIENT_H
