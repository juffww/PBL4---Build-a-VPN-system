#include "mainwindow.h"
#include "vpn_client.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QTextEdit>
#include <QGroupBox>
#include <QProgressBar>
#include <QStatusBar>
#include <QMenuBar>
#include <QAction>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QMessageBox>
#include <QTimer>
#include <QSettings>
#include <QIcon>
#include <QCloseEvent>
#include <QNetworkInterface>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QHostAddress>
#include <QRadioButton>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), isConnected(false), isHideMessageShown(false),
    networkManager(nullptr), currentReply(nullptr), vpnClient(nullptr),
    systemTrayIcon(nullptr), statsTimer(nullptr), ipCheckTimer(nullptr),
    connectionTimeStarted(false),
    totalDownload(0), totalUpload(0), trafficRunning(false), trafficButton(nullptr), webTrafficTimer(nullptr)
{
    networkManager = new QNetworkAccessManager(this);
    vpnClient = new VPNClient(this);
    setupUI();
    setupSystemTray();
    setupTimer();
    setupVPNClientConnections();
    loadSettings();
    updateConnectionStatus();
    updateRealIP();
    getPublicIP();
}

MainWindow::~MainWindow()
{
    saveSettings();
    if (vpnClient) {
        vpnClient->disconnectFromServer();
        vpnClient->shutdown();
    }
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void MainWindow::setupVPNClientConnections()
{
    connect(vpnClient, &VPNClient::connected, this, [this]() {
        logTextEdit->append("[INFO] Đã kết nối socket tới server");
        logTextEdit->append("[INFO] Đang thực hiện authentication...");
    });

    connect(vpnClient, &VPNClient::authenticationResult, this, [this](bool success, const QString& message) {
        progressBar->setVisible(false);
        connectButton->setEnabled(true);

        if (success) {
            isConnected = true;

            connectionStartTime = QTime::currentTime();
            connectionTimeStarted = true;

            if (message.contains("VPN_IP:")) {
                int start = message.indexOf("VPN_IP:") + 7;
                int end = message.indexOf("|", start);
                if (end == -1) end = message.indexOf("\n", start);
                if (end == -1) end = message.length();

                currentVpnIP = message.mid(start, end - start).trimmed();
                logTextEdit->append(QString("[INFO] Được cấp VPN IP: %1").arg(currentVpnIP));
            }

            updateConnectionStatus();
            logTextEdit->append(QString("[SUCCESS] Kết nối VPN thành công: %1").arg(message));

            if (systemTrayIcon) {
                systemTrayIcon->showMessage("VPN Client",
                                            QString("Kết nối VPN thành công!\nVPN IP: %1").arg(currentVpnIP),
                                            QSystemTrayIcon::Information, 3000);
            }

            QTimer::singleShot(5000, this, &MainWindow::getPublicIP);

        } else {
            isConnected = false;
            currentVpnIP.clear();
            connectionTimeStarted = false;
            updateConnectionStatus();

            logTextEdit->append(QString("[ERROR] Authentication failed: %1").arg(message));
            QMessageBox::warning(this, "Xác thực thất bại", message);
        }
    });

    connect(vpnClient, &VPNClient::disconnected, this, [this]() {
        isConnected = false;
        currentVpnIP.clear();
        connectionTimeStarted = false;

        updateConnectionStatus();
        progressBar->setVisible(false);
        connectButton->setEnabled(true);

        logTextEdit->append("[INFO] Đã ngắt kết nối khỏi server");

        updateRealIP();
        getPublicIP();
    });

    connect(vpnClient, &VPNClient::error, this, [this](const QString& errorMsg) {
        logTextEdit->append(QString("[ERROR] %1").arg(errorMsg));

        progressBar->setVisible(false);
        connectButton->setEnabled(true);
        isConnected = false;
        currentVpnIP.clear();
        connectionTimeStarted = false;
        updateConnectionStatus();

        QMessageBox::warning(this, "Lỗi kết nối", errorMsg);
    });

    connect(vpnClient, &VPNClient::messageReceived, this, [this](const QString& message) {
        logTextEdit->append(QString("[SERVER] %1").arg(message));
        if (message.startsWith("VPN_IP|")) {
            QStringList parts = message.split("|");
            if (parts.size() >= 2) {
                currentVpnIP = parts[1];
                updateConnectionStatus();
                logTextEdit->append(QString("[INFO] VPN IP updated: %1").arg(currentVpnIP));
            }
        }
        else if (message.startsWith("STATUS|")) {
            logTextEdit->append(QString("[INFO] Status: %1").arg(message.mid(7)));
        }
    });

    connect(vpnClient, &VPNClient::vpnIPAssigned, this, [this](const QString& vpnIP) {
        currentVpnIP = vpnIP;
        updateConnectionStatus();
        logTextEdit->append(QString("[INFO] VPN IP assigned: %1").arg(vpnIP));
    });

    connect(vpnClient, &VPNClient::statusReceived, this, [this](const QString& status) {
        logTextEdit->append(QString("[STATUS] %1").arg(status));
    });
}

void MainWindow::connectToVPN()
{
    if (isConnected) {
        disconnectFromVPN();
        return;
    }

    QString serverKey;
    if (usRadioButton->isChecked()) {
        serverKey = "servers/us_server_ip";
    } else if (sgRadioButton->isChecked()) {
        serverKey = "servers/sg_server_ip";
    } else if (ukRadioButton->isChecked()) {
        serverKey = "servers/uk_server_ip";
    } else {
        QMessageBox::warning(this, "Chưa chọn vùng",
                             "Vui lòng chọn một vùng máy chủ trước khi kết nối.");
        return;
    }

    QSettings settings("win_config.ini", QSettings::IniFormat);
    QString host = settings.value(serverKey).toString().trimmed();
    int port = settings.value("servers/default_port", 5000).toInt();

    logTextEdit->append(QString("[DEBUG] Config file: win_config.ini"));
    logTextEdit->append(QString("[DEBUG] Server key: %1").arg(serverKey));
    logTextEdit->append(QString("[DEBUG] Host read: '%1'").arg(host));
    logTextEdit->append(QString("[DEBUG] Port: %1").arg(port));

    if (host.isEmpty()) {
        QMessageBox::critical(this, "Lỗi cấu hình",
                              QString("Không tìm thấy IP cho key '%1' trong file mac_config.ini.\n\n"
                                      "Vui lòng kiểm tra:\n"
                                      "1. File tồn tại tại: win_config.ini\n"
                                      "2. File có section [servers]\n"
                                      "3. Có key: %1=<IP_ADDRESS>").arg(serverKey));

        logTextEdit->append("[ERROR] Host is empty!");
        return;
    }

    QHostAddress testAddr(host);
    if (testAddr.isNull()) {
        QMessageBox::critical(this, "Lỗi IP",
                              QString("IP không hợp lệ: %1").arg(host));
        logTextEdit->append(QString("[ERROR] Invalid IP address: %1").arg(host));
        return;
    }

    if (port <= 0 || port > 65535) {
        QMessageBox::critical(this, "Lỗi Port",
                              QString("Port không hợp lệ: %1 (phải từ 1-65535)").arg(port));
        return;
    }

    serverEdit->setText(QString("%1:%2").arg(host).arg(port));

    QString username = usernameEdit->text().trimmed();
    QString password = passwordEdit->text().trimmed();

    if (username.isEmpty()) {
        QMessageBox::warning(this, "Lỗi", "Vui lòng nhập tên đăng nhập");
        usernameEdit->setFocus();
        return;
    }
    if (password.isEmpty()) {
        QMessageBox::warning(this, "Lỗi", "Vui lòng nhập mật khẩu");
        passwordEdit->setFocus();
        return;
    }

    connectButton->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setRange(0, 0);

    logTextEdit->append("[INFO] Bắt đầu kết nối VPN...");
    logTextEdit->append(QString("[INFO] => Connecting to: %1:%2").arg(host).arg(port));
    logTextEdit->append(QString("[INFO] => Username: %1").arg(username));

    QTimer::singleShot(10000, this, [this, host, port]() {
        if (!isConnected && !vpnClient->isConnected()) {
            logTextEdit->append("[ERROR] Connection timeout after 10 seconds");
            logTextEdit->append(QString("[ERROR] Could not connect to %1:%2").arg(host).arg(port));
            progressBar->setVisible(false);
            connectButton->setEnabled(true);

            QMessageBox::critical(this, "Lỗi kết nối",
                                  QString("Không thể kết nối đến server:\n%1:%2\n\n"
                                          "Kiểm tra:\n"
                                          "1. Server có đang chạy không?\n"
                                          "2. Firewall có chặn không?\n"
                                          "3. IP và Port có đúng không?").arg(host).arg(port));
        }
    });

    if (!isConnected && initialISP_IP.isEmpty() && !currentPublicIP.isEmpty()) {
        initialISP_IP = currentPublicIP;
        logTextEdit->append(QString("[DEBUG] IP ISP gốc: %1").arg(initialISP_IP));
    }

    if (networkManager) {
        delete networkManager;
        networkManager = new QNetworkAccessManager(this);
    }

    vpnClient->connectToServer(host, port, username, password);
}


bool MainWindow::isServerReachable(const QString& host)
{
    if (host == "localhost" || host == "127.0.0.1") {
        return true;
    }

    QHostAddress address(host);
    if (address.isNull()) {
        return false;
    }

    quint32 ip = address.toIPv4Address();

    if ((ip >= 0x0A000000 && ip <= 0x0AFFFFFF) ||      // 10.x.x.x
        (ip >= 0xAC100000 && ip <= 0xAC1FFFFF) ||      // 172.16.x.x - 172.31.x.x
        (ip >= 0xC0A80000 && ip <= 0xC0A8FFFF)) {      // 192.168.x.x
        return true;
    }

    return true;
}
void MainWindow::disconnectFromVPN()
{
    if (vpnClient) {
        vpnClient->disconnectFromServer();
        vpnClient->stopTUNTrafficGeneration();
    }

    isConnected = false;
    currentVpnIP.clear();

    trafficButton->setText("Traffic (Disconnected)");
    trafficButton->setEnabled(false);
    trafficRunning = false;

    updateConnectionStatus();
    progressBar->setVisible(false);
    connectButton->setText("Kết nối");
    connectButton->setEnabled(true);

    logTextEdit->append("[INFO] Đã ngắt kết nối VPN!");
    logTextEdit->append("[INFO] Traffic generation stopped.");

    updateRealIP();
    getPublicIP();
}

void MainWindow::clearLog()
{
    logTextEdit->clear();
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, "Về VPN Client",
                       "VPN Client v1.0\n\n"
                       "Ứng dụng VPN Client đơn giản được xây dựng với Qt.\n"
                       "Kết nối tới máy chủ VPN với cấp phát IP động.\n\n"
                       "© 2025 VPN Client");
}

void MainWindow::toggleWindow()
{
    if (isVisible()) {
        hide();
    } else {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::updateStats()
{
    if (isConnected) {
        static quint64 totalDownload = 0;
        static quint64 totalUpload = 0;
        totalDownload += (rand() % 1000 + 100);
        totalUpload += (rand() % 500 + 50);

        downloadLabel->setText(QString("↓ %1 KB").arg(totalDownload));
        uploadLabel->setText(QString("↑ %1 KB").arg(totalUpload));

        if (connectionTimeStarted) {
            int totalSeconds = connectionStartTime.secsTo(QTime::currentTime());
            if (totalSeconds < 0) {
                totalSeconds += 24 * 3600;
            }

            int hours = totalSeconds / 3600;
            int minutes = (totalSeconds % 3600) / 60;
            int seconds = totalSeconds % 60;

            connectionTimeLabel->setText(QString("Thời gian: %1:%2:%3")
                                             .arg(hours, 2, 10, QChar('0'))
                                             .arg(minutes, 2, 10, QChar('0'))
                                             .arg(seconds, 2, 10, QChar('0')));
        }
    } else {
        totalDownload = 0;
        totalUpload = 0;

        latencyLabel->setText("Ping: 100 ms");
        packetLossLabel->setText("Loss: 0 %");
        packetLossLabel->setStyleSheet("color: #555;");

        downloadLabel->setText("↓ 0 KB");
        uploadLabel->setText("↑ 0 KB");
        connectionTimeLabel->setText("Thời gian: 00:00:00");
        connectionTimeStarted = false;
    }
}

void MainWindow::updateRealIP()
{
    currentRealIP = getCurrentLocalIP();
    realIPLabel->setText(QString("IP thật: %1").arg(currentRealIP));
}

void MainWindow::checkCurrentIP()
{
    updateRealIP();
    getPublicIP();
}

QString MainWindow::getCurrentLocalIP()
{
    QString localIP = "127.0.0.1";
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    // Duyệt qua tất cả các card mạng
    for (const QNetworkInterface &interface : interfaces) {
        // Bỏ qua nếu card mạng chưa bật hoặc là Loopback
        if (!(interface.flags() & QNetworkInterface::IsUp) ||
            !(interface.flags() & QNetworkInterface::IsRunning) ||
            (interface.flags() & QNetworkInterface::IsLoopBack)) {
            continue;
        }

        // Lọc bỏ các tên card mạng thường là VPN
        QString name = interface.humanReadableName();
        if (name.contains("MyVPN", Qt::CaseInsensitive) ||
            name.contains("Wintun", Qt::CaseInsensitive) ||
            name.contains("TAP", Qt::CaseInsensitive) ||
            name.contains("Tun", Qt::CaseInsensitive)) {
            continue;
        }

        QList<QNetworkAddressEntry> entries = interface.addressEntries();
        for (const QNetworkAddressEntry &entry : entries) {
            QHostAddress ip = entry.ip();

            // Chỉ lấy IPv4
            if (ip.protocol() != QAbstractSocket::IPv4Protocol) continue;

            QString ipString = ip.toString();

            // Lọc cứng: Bỏ qua dải IP của VPN (10.8.0.x)
            if (ipString.startsWith("10.8.0.")) {
                continue;
            }

            // Nếu tìm thấy IP hợp lệ (thường bắt đầu 192.168 hoặc 10.x hoặc 172.x)
            // Trả về ngay lập tức
            return ipString;
        }
    }

    return localIP;
}

void MainWindow::getPublicIP()
{
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }

    QNetworkRequest request(QUrl("https://api.ipify.org?format=json"));
    request.setRawHeader("User-Agent", "VPN-Client/1.0");

    currentReply = networkManager->get(request);
    connect(currentReply, &QNetworkReply::finished, this, &MainWindow::onPublicIPReceived);
}

void MainWindow::onPublicIPReceived()
{
    if (!currentReply) return;

    if (currentReply->error() == QNetworkReply::NoError) {
        QByteArray data = currentReply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject obj = doc.object();

        if (obj.contains("ip")) {
            currentPublicIP = obj["ip"].toString();
            publicIPLabel->setText(QString("IP công cộng: %1").arg(currentPublicIP));

            logTextEdit->append(QString("[SUCCESS] Đã lấy IP công cộng mới: %1").arg(currentPublicIP));
        }
    } else {
        QString errStr = currentReply->errorString();
        publicIPLabel->setText("IP công cộng: Lỗi mạng");
        logTextEdit->append(QString("[WARN] Không thể lấy IP công cộng. Lỗi: %1").arg(errStr));

        QTimer::singleShot(5000, this, &MainWindow::getPublicIP);
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void MainWindow::setupUI()
{
    setWindowTitle("VPN Client - Enhanced");
    setMinimumSize(600, 550);
    resize(700, 600);

    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    QGroupBox *ipGroup = new QGroupBox("Thông tin IP");
    QGridLayout *ipLayout = new QGridLayout(ipGroup);

    realIPLabel = new QLabel("IP thật: Đang kiểm tra...");
    realIPLabel->setStyleSheet("QLabel { font-weight: bold; color: blue; }");
    ipLayout->addWidget(realIPLabel, 0, 0);

    vpnIPLabel = new QLabel("VPN IP: Chưa kết nối");
    vpnIPLabel->setStyleSheet("QLabel { font-weight: bold; color: green; }");
    ipLayout->addWidget(vpnIPLabel, 0, 1);

    publicIPLabel = new QLabel("IP công cộng: Đang kiểm tra...");
    publicIPLabel->setStyleSheet("QLabel { font-weight: bold; color: red; }");
    ipLayout->addWidget(publicIPLabel, 1, 0, 1, 2);

    QPushButton *refreshIPButton = new QPushButton("Làm mới IP");
    connect(refreshIPButton, &QPushButton::clicked, this, &MainWindow::checkCurrentIP);
    ipLayout->addWidget(refreshIPButton, 2, 0, 1, 2);

    mainLayout->addWidget(ipGroup);

    QGroupBox *statusGroup = new QGroupBox("Trạng thái kết nối");
    QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);

    statusLabel = new QLabel("Chưa kết nối");
    statusLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 14px; color: red; }");
    statusLayout->addWidget(statusLabel);

    QHBoxLayout *statsLayout = new QHBoxLayout();
    downloadLabel = new QLabel("↓ 0 KB");
    uploadLabel = new QLabel("↑ 0 KB");

    latencyLabel = new QLabel("Ping: - ms");
    //latencyLabel->setStyleSheet("color: #555;");

    packetLossLabel = new QLabel("Loss: - %");
    //packetLossLabel->setStyleSheet("color: #555;");

    connectionTimeLabel = new QLabel("Thời gian: 00:00:00");

    statsLayout->addWidget(downloadLabel);
    statsLayout->addSpacing(15);
    statsLayout->addWidget(uploadLabel);
    // --- THÊM VÀO LAYOUT ---
    statsLayout->addSpacing(15);
    statsLayout->addWidget(latencyLabel);
    statsLayout->addSpacing(15);
    statsLayout->addWidget(packetLossLabel);
    // -----------------------
    statsLayout->addStretch();
    statsLayout->addWidget(connectionTimeLabel);
    statusLayout->addLayout(statsLayout);

    mainLayout->addWidget(statusGroup);

    regionGroup = new QGroupBox("Chuyển vùng");
    QHBoxLayout *regionLayout = new QHBoxLayout(regionGroup);

    usRadioButton = new QRadioButton("Mỹ");
    sgRadioButton = new QRadioButton("Singapore");
    ukRadioButton = new QRadioButton("Anh");

    regionLayout->addWidget(usRadioButton);
    regionLayout->addWidget(sgRadioButton);
    regionLayout->addWidget(ukRadioButton);
    regionLayout->addStretch();

    mainLayout->addWidget(regionGroup);

    connect(usRadioButton, &QRadioButton::toggled, this, &MainWindow::onRegionChanged);
    connect(sgRadioButton, &QRadioButton::toggled, this, &MainWindow::onRegionChanged);
    connect(ukRadioButton, &QRadioButton::toggled, this, &MainWindow::onRegionChanged);

    QGroupBox *settingsGroup = new QGroupBox("Cài đặt kết nối");
    QGridLayout *settingsLayout = new QGridLayout(settingsGroup);

    settingsLayout->addWidget(new QLabel("Máy chủ:"), 0, 0);
    serverEdit = new QLineEdit("");
    serverEdit->setReadOnly(true);
    serverEdit->setStyleSheet("QLineEdit { background-color: #f0f0f0; }");
    settingsLayout->addWidget(serverEdit, 0, 1);

    settingsLayout->addWidget(new QLabel("Tên đăng nhập:"), 1, 0);
    usernameEdit = new QLineEdit();
    usernameEdit->setPlaceholderText("Nhập tên đăng nhập");
    settingsLayout->addWidget(usernameEdit, 1, 1);

    settingsLayout->addWidget(new QLabel("Mật khẩu:"), 2, 0);
    passwordEdit = new QLineEdit();
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("Nhập mật khẩu");
    settingsLayout->addWidget(passwordEdit, 2, 1);

    settingsLayout->addWidget(new QLabel("Giao thức:"), 3, 0);
    protocolCombo = new QComboBox();
    protocolCombo->addItems({"VPN Protocol", "OpenVPN", "WireGuard"});
    protocolCombo->setCurrentIndex(0);
    settingsLayout->addWidget(protocolCombo, 3, 1);

    mainLayout->addWidget(settingsGroup);

    QHBoxLayout *buttonLayout = new QHBoxLayout();

    connectButton = new QPushButton("Kết nối");
    connectButton->setStyleSheet(
        "QPushButton { font-weight: bold; padding: 10px 20px; font-size: 14px; }"
        "QPushButton:hover { background-color: #4CAF50; color: white; }"
        );
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::connectToVPN);
    buttonLayout->addWidget(connectButton);

    // Nút Traffic chỉ hiển thị trạng thái
    trafficButton = new QPushButton("Traffic (Disconnected)");
    trafficButton->setEnabled(false);
    trafficButton->setStyleSheet(
        "QPushButton { font-weight: bold; padding: 10px 20px; font-size: 14px; }"
        "QPushButton:disabled { background-color: #cccccc; }"
        );
    buttonLayout->addWidget(trafficButton);

    QPushButton *clearLogButton = new QPushButton("Xóa log");
    connect(clearLogButton, &QPushButton::clicked, this, &MainWindow::clearLog);
    buttonLayout->addWidget(clearLogButton);

    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);


    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    QGroupBox *logGroup = new QGroupBox("Nhật ký kết nối");
    QVBoxLayout *logLayout = new QVBoxLayout(logGroup);

    logTextEdit = new QTextEdit();
    logTextEdit->setMaximumHeight(120);
    logTextEdit->setReadOnly(true);
    logTextEdit->append("VPN Client Enhanced đã khởi động...");
    logTextEdit->append("Server mặc định: 192.168.1.100:1194 với cấp phát IP động");
    logLayout->addWidget(logTextEdit);

    mainLayout->addWidget(logGroup);

    QMenuBar *menuBar = this->menuBar();
    QMenu *fileMenu = menuBar->addMenu("Tệp");
    QAction *exitAction = fileMenu->addAction("Thoát");
    connect(exitAction, &QAction::triggered, this, &QWidget::close);

    QMenu *helpMenu = menuBar->addMenu("Trợ giúp");
    QAction *aboutAction = helpMenu->addAction("Về chương trình");
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);

    statusBar()->showMessage("Sẵn sàng kết nối tới VPN server với IP động");
}

bool MainWindow::parseServerAddress(const QString& serverInput, QString& host, int& port)
{
    if (serverInput.isEmpty()) {
        return false;
    }

    QStringList parts = serverInput.split(":");
    host = parts[0].trimmed();

    if (host.isEmpty()) {
        return false;
    }

    port = 5000;

    if (parts.size() > 1) {
        bool ok;
        int parsedPort = parts[1].toInt(&ok);
        if (ok && parsedPort > 0 && parsedPort <= 65535) {
            port = parsedPort;
        } else {
            return false;
        }
    }

    return true;
}

void MainWindow::setupSystemTray()
{
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        systemTrayIcon = new QSystemTrayIcon(this);
        systemTrayIcon->setToolTip("VPN Client Enhanced");

        QMenu *trayMenu = new QMenu(this);
        QAction *showAction = trayMenu->addAction("Hiện/Ẩn cửa sổ");
        connect(showAction, &QAction::triggered, this, &MainWindow::toggleWindow);

        trayMenu->addSeparator();
        QAction *connectAction = trayMenu->addAction("Kết nối");
        connect(connectAction, &QAction::triggered, this, &MainWindow::connectToVPN);

        QAction *disconnectAction = trayMenu->addAction("Ngắt kết nối");
        connect(disconnectAction, &QAction::triggered, this, &MainWindow::disconnectFromVPN);

        trayMenu->addSeparator();
        QAction *exitAction = trayMenu->addAction("Thoát");
        connect(exitAction, &QAction::triggered, this, &QWidget::close);

        systemTrayIcon->setContextMenu(trayMenu);
        systemTrayIcon->show();

        connect(systemTrayIcon, &QSystemTrayIcon::activated,
                [this](QSystemTrayIcon::ActivationReason reason) {
                    if (reason == QSystemTrayIcon::DoubleClick) {
                        toggleWindow();
                    }
                });
    } else {
        systemTrayIcon = nullptr;
    }
}

void MainWindow::setupTimer()
{
    statsTimer = new QTimer(this);
    connect(statsTimer, &QTimer::timeout, this, &MainWindow::updateStats);
    statsTimer->start(1000);

    ipCheckTimer = new QTimer(this);
    connect(ipCheckTimer, &QTimer::timeout, this, &MainWindow::checkCurrentIP);
    ipCheckTimer->start(60000); // Cập nhật mỗi phút
}

void MainWindow::updateConnectionStatus()
{
    if (isConnected) {
        statusLabel->setText("Đã kết nối");
        statusLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 14px; color: green; }");
        connectButton->setText("Ngắt kết nối");
        connectButton->setStyleSheet(
            "QPushButton { font-weight: bold; padding: 10px 20px; font-size: 14px; background-color: #f44336; color: white; }"
            "QPushButton:hover { background-color: #da190b; }"
            );

        if (!currentVpnIP.isEmpty()) {
            vpnIPLabel->setText(QString("VPN IP: %1").arg(currentVpnIP));
        } else {
            vpnIPLabel->setText("VPN IP: Đã kết nối");
        }

        if (systemTrayIcon) {
            systemTrayIcon->setToolTip(QString("VPN Client - Đã kết nối (%1)").arg(currentVpnIP));
        }
    } else {
        statusLabel->setText("Chưa kết nối");
        statusLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 14px; color: red; }");
        connectButton->setText("Kết nối");
        connectButton->setStyleSheet(
            "QPushButton { font-weight: bold; padding: 10px 20px; font-size: 14px; }"
            "QPushButton:hover { background-color: #4CAF50; color: white; }"
            );
        vpnIPLabel->setText("VPN IP: Chưa kết nối");

        if (systemTrayIcon) {
            systemTrayIcon->setToolTip("VPN Client - Chưa kết nối");
        }
    }
}

void MainWindow::loadSettings()
{
    QSettings settings;
    usernameEdit->setText(settings.value("username", "").toString());
    protocolCombo->setCurrentText(settings.value("protocol", "VPN Protocol").toString());
    restoreGeometry(settings.value("geometry").toByteArray());
}

void MainWindow::saveSettings()
{
    QSettings settings;
    settings.setValue("username", usernameEdit->text());
    settings.setValue("protocol", protocolCombo->currentText());
    settings.setValue("geometry", saveGeometry());
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (systemTrayIcon && systemTrayIcon->isVisible()) {
        hide();
        event->ignore();
        if (!isHideMessageShown) {
            systemTrayIcon->showMessage("VPN Client",
                                        "Ứng dụng đã được thu nhỏ xuống system tray.",
                                        QSystemTrayIcon::Information, 3000);
            isHideMessageShown = true;
        }
    } else {
        event->accept();
    }
}

void MainWindow::onRegionChanged()
{
    connectButton->setEnabled(true);

    if (isConnected) {
        QMessageBox::information(this, "Thông báo", "Bạn sẽ được ngắt kết nối để thay đổi vùng máy chủ.");
        disconnectFromVPN();
    }
}
