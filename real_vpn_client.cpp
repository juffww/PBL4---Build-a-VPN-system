#include "real_vpn_client.h"
#include <QHostAddress>
#include <QDebug>
#include <QThread>

RealVPNClient::RealVPNClient(QObject *parent)
    : QObject(parent), tunFd(-1), tunCreated(false), isRunning(false),
      isAuthenticated(false), bytesReceived(0), bytesSent(0),
      packetsReceived(0), packetsSent(0), packetThread(nullptr)
{
    controlSocket = new QTcpSocket(this);
    pingTimer = new QTimer(this);
    statsTimer = new QTimer(this);

    connect(controlSocket, &QTcpSocket::connected, this, &RealVPNClient::onControlConnected);
    connect(controlSocket, &QTcpSocket::disconnected, this, &RealVPNClient::onControlDisconnected);
    connect(controlSocket, &QTcpSocket::readyRead, this, &RealVPNClient::onControlReadyRead);
    connect(controlSocket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &RealVPNClient::onControlError);

    connect(pingTimer, &QTimer::timeout, this, &RealVPNClient::sendPing);
    connect(statsTimer, &QTimer::timeout, this, &RealVPNClient::updateStats);

    pingTimer->setInterval(30000); // 30s
    statsTimer->setInterval(1000);  // 1s
}

RealVPNClient::~RealVPNClient()
{
    disconnectFromServer();
}

void RealVPNClient::connectToServer(const QString& host, int port, const QString& user, const QString& pass)
{
    if (controlSocket->state() != QAbstractSocket::UnconnectedState) {
        disconnectFromServer();
    }

    username = user;
    password = pass;
    serverIP = host;

    qDebug() << "Connecting to VPN server:" << host << ":" << port;
    controlSocket->connectToHost(host, port);
}

void RealVPNClient::disconnectFromServer()
{
    isRunning = false;
    pingTimer->stop();
    statsTimer->stop();

    stopPacketProcessing();
    closeTunInterface();
    restoreRoutes();

    if (controlSocket->state() != QAbstractSocket::UnconnectedState) {
        sendControlMessage("DISCONNECT");
        controlSocket->disconnectFromHost();
        controlSocket->waitForDisconnected(3000);
    }

    isAuthenticated = false;
}

bool RealVPNClient::createTunInterface()
{
    // Mở /dev/net/tun - cần quyền root
    tunFd = open("/dev/net/tun", O_RDWR);
    if (tunFd < 0) {
        emit error("Cannot open /dev/net/tun - requires root privileges");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "vpn%d", IFNAMSIZ-1);

    if (ioctl(tunFd, TUNSETIFF, (void*)&ifr) < 0) {
        emit error(QString("Cannot create TUN interface: %1").arg(strerror(errno)));
        close(tunFd);
        tunFd = -1;
        return false;
    }

    tunInterfaceName = ifr.ifr_name;
    tunCreated = true;

    qDebug() << "Created TUN interface:" << tunInterfaceName;
    return true;
}

bool RealVPNClient::configureTunInterface(const QString& ip, const QString& gateway)
{
    if (!tunCreated) return false;

    vpnIP = ip;

    // Set IP address
    QString cmd = QString("ip addr add %1/24 dev %2").arg(ip, tunInterfaceName);
    if (!executeCommand(cmd)) {
        emit error("Cannot set IP address for TUN interface");
        return false;
    }

    // Bring interface up
    cmd = QString("ip link set dev %1 up").arg(tunInterfaceName);
    if (!executeCommand(cmd)) {
        emit error("Cannot bring TUN interface up");
        return false;
    }

    // Set routes
    if (!setRoutes()) {
        emit error("Cannot set VPN routes");
        return false;
    }

    qDebug() << "Configured TUN interface with IP:" << ip;
    return true;
}

void RealVPNClient::closeTunInterface()
{
    if (tunFd >= 0) {
        close(tunFd);
        tunFd = -1;
    }
    tunCreated = false;
}

bool RealVPNClient::setRoutes()
{
    // Backup current default route
    executeCommand("ip route show default > /tmp/vpn_backup_route");

    // Add route to VPN server through original gateway
    QString cmd = QString("ip route add %1/32 via $(ip route | grep default | awk '{print $3}' | head -n1)")
                  .arg(serverIP);
    executeCommand(cmd);

    // Set new default route through VPN
    executeCommand("ip route del default");
    cmd = QString("ip route add default dev %1").arg(tunInterfaceName);
    if (!executeCommand(cmd)) {
        return false;
    }

    // Set DNS
    executeCommand("cp /etc/resolv.conf /tmp/vpn_backup_resolv.conf");
    executeCommand("echo 'nameserver 8.8.8.8' > /etc/resolv.conf");

    return true;
}

bool RealVPNClient::restoreRoutes()
{
    if (tunInterfaceName.isEmpty()) return true;

    // Restore original routes
    QString cmd = QString("ip route del default dev %1").arg(tunInterfaceName);
    executeCommand(cmd);

    executeCommand("ip route add default via $(cat /tmp/vpn_backup_route | awk '{print $3}' | head -n1)");
    executeCommand("cp /tmp/vpn_backup_resolv.conf /etc/resolv.conf");

    return true;
}

void RealVPNClient::onControlConnected()
{
    qDebug() << "Control connection established";
    emit connected();
}

void RealVPNClient::onControlDisconnected()
{
    qDebug() << "Control connection lost";
    emit disconnected();

    stopPacketProcessing();
    closeTunInterface();
    restoreRoutes();
}

void RealVPNClient::onControlReadyRead()
{
    while (controlSocket->canReadLine()) {
        QString message = controlSocket->readLine().trimmed();
        handleServerMessage(message);
    }
}

void RealVPNClient::handleServerMessage(const QString& message)
{
    qDebug() << "Server message:" << message;

    if (message.startsWith("WELCOME|")) {
        // Server ready, start authentication
        authenticate();
    }
    else if (message.startsWith("AUTH_OK|")) {
        isAuthenticated = true;

        // Parse VPN IP
        if (message.contains("VPN_IP:")) {
            int start = message.indexOf("VPN_IP:") + 7;
            int end = message.indexOf("|", start);
            if (end == -1) end = message.length();

            QString assignedIP = message.mid(start, end - start).trimmed();

            // Create and configure TUN interface
            if (createTunInterface() && configureTunInterface(assignedIP, serverIP)) {
                startPacketProcessing();
                pingTimer->start();
                statsTimer->start();
                emit authenticated(true, QString("VPN connected with IP: %1").arg(assignedIP));
                emit vpnIPAssigned(assignedIP);
            } else {
                emit error("Failed to configure TUN interface");
            }
        }
    }
    else if (message.startsWith("AUTH_FAIL|")) {
        isAuthenticated = false;
        emit authenticated(false, message.mid(10));
    }
    else if (message.startsWith("PONG")) {
        // Keep-alive response
    }
}

void RealVPNClient::authenticate()
{
    QString authMsg = QString("AUTH %1 %2").arg(username, password);
    sendControlMessage(authMsg);
}

void RealVPNClient::sendControlMessage(const QString& message)
{
    if (controlSocket->state() == QAbstractSocket::ConnectedState) {
        controlSocket->write((message + "\n").toUtf8());
        controlSocket->flush();
    }
}

void RealVPNClient::startPacketProcessing()
{
    if (!packetThread && tunFd >= 0) {
        isRunning = true;
        packetThread = QThread::create([this]() { processPackets(); });
        packetThread->start();
    }
}

void RealVPNClient::stopPacketProcessing()
{
    isRunning = false;
    if (packetThread) {
        packetThread->quit();
        packetThread->wait();
        delete packetThread;
        packetThread = nullptr;
    }
}

void RealVPNClient::processPackets()
{
    char buffer[2048];
    fd_set readfds;

    while (isRunning && tunFd >= 0) {
        FD_ZERO(&readfds);
        FD_SET(tunFd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = select(tunFd + 1, &readfds, nullptr, nullptr, &timeout);

        if (ready > 0 && FD_ISSET(tunFd, &readfds)) {
            // Đọc packet từ TUN interface
            ssize_t len = read(tunFd, buffer, sizeof(buffer));
            if (len > 0) {
                {
                    QMutexLocker lock(&statsMutex);
                    bytesSent += len;
                    packetsSent++;
                }

                // Gửi packet qua control connection tới server
                // Ở đây bạn cần implement protocol để gửi packet data
                // Ví dụ: DATA|<base64_encoded_packet>
                QByteArray packetData = QByteArray(buffer, len).toBase64();
                QString dataMsg = QString("DATA|%1").arg(QString::fromUtf8(packetData));
                sendControlMessage(dataMsg);
            }
        }

        // Kiểm tra có data từ server không (được xử lý trong control connection)
        // Server sẽ gửi packet về dạng DATA|<base64_packet>
        // và chúng ta sẽ write vào TUN interface
    }
}

void RealVPNClient::onControlError(QAbstractSocket::SocketError error)
{
    QString errorMsg;
    switch (error) {
        case QAbstractSocket::ConnectionRefusedError:
            errorMsg = "Server refused connection";
            break;
        case QAbstractSocket::RemoteHostClosedError:
            errorMsg = "Server closed connection";
            break;
        case QAbstractSocket::HostNotFoundError:
            errorMsg = "Server not found";
            break;
        default:
            errorMsg = controlSocket->errorString();
            break;
    }

    emit this->error(errorMsg);
}

void RealVPNClient::sendPing()
{
    sendControlMessage("PING");
}

void RealVPNClient::updateStats()
{
    QMutexLocker lock(&statsMutex);
    emit statsUpdated(bytesReceived, bytesSent, packetsReceived, packetsSent);
}

bool RealVPNClient::executeCommand(const QString& command)
{
    qDebug() << "Executing:" << command;
    int result = system(command.toUtf8().constData());
    return (result == 0);
}
