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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), isConnected(false), isHideMessageShown(false),
      networkManager(nullptr), currentReply(nullptr), vpnClient(nullptr),
      systemTrayIcon(nullptr), statsTimer(nullptr), ipCheckTimer(nullptr),
      connectionTimeStarted(false),
      totalDownload(0), totalUpload(0)
{
    // Khởi tạo Network Manager
    networkManager = new QNetworkAccessManager(this);

    // Khởi tạo VPN Client
    vpnClient = new VPNClient(this);

    setupUI();
    setupSystemTray();
    setupTimer();
    setupVPNClientConnections();
    loadSettings();
    updateConnectionStatus();

    // Lấy IP hiện tại khi khởi động
    updateRealIP();
    getPublicIP();
}

MainWindow::~MainWindow()
{
    saveSettings();
    if (vpnClient) {
        vpnClient->disconnectFromServer();
    }
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void MainWindow::setupVPNClientConnections()
{
    // Khi socket connected tới server (chỉ log, không gọi lại connectToServer)
    connect(vpnClient, &VPNClient::connected, this, [this]() {
        logTextEdit->append("[INFO] Đã kết nối socket tới server");
        logTextEdit->append("[INFO] Đang thực hiện authentication...");
    });

    // Khi nhận kết quả authentication - đây là signal quan trọng nhất
    connect(vpnClient, &VPNClient::authenticationResult, this, [this](bool success, const QString& message) {
        progressBar->setVisible(false);
        connectButton->setEnabled(true);

        if (success) {
            isConnected = true;

            // RESET THỜI GIAN KẾT NỐI về 0
            connectionStartTime = QTime::currentTime();
            connectionTimeStarted = true;

            // Parse VPN IP từ message
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

            // Hiện thông báo system tray
            if (systemTrayIcon) {
                systemTrayIcon->showMessage("VPN Client",
                    QString("Kết nối VPN thành công!\nVPN IP: %1").arg(currentVpnIP),
                    QSystemTrayIcon::Information, 3000);
            }

            // Kiểm tra IP công cộng sau khi kết nối
            QTimer::singleShot(2000, this, &MainWindow::getPublicIP);

        } else {
            // Authentication thất bại
            isConnected = false;
            currentVpnIP.clear();
            connectionTimeStarted = false;
            updateConnectionStatus();

            logTextEdit->append(QString("[ERROR] Authentication failed: %1").arg(message));
            QMessageBox::warning(this, "Xác thực thất bại", message);
        }
    });

    // Khi ngắt kết nối
    connect(vpnClient, &VPNClient::disconnected, this, [this]() {
        isConnected = false;
        currentVpnIP.clear();
        connectionTimeStarted = false; // Reset timer khi disconnect

        updateConnectionStatus();
        progressBar->setVisible(false);
        connectButton->setEnabled(true);

        logTextEdit->append("[INFO] Đã ngắt kết nối khỏi server");

        // Cập nhật lại IP thật và public IP
        updateRealIP();
        getPublicIP();
    });

    // Khi có lỗi kết nối
    connect(vpnClient, &VPNClient::error, this, [this](const QString& errorMsg) {
        logTextEdit->append(QString("[ERROR] %1").arg(errorMsg));

        // Reset trạng thái
        progressBar->setVisible(false);
        connectButton->setEnabled(true);
        isConnected = false;
        currentVpnIP.clear();
        connectionTimeStarted = false;
        updateConnectionStatus();

        QMessageBox::warning(this, "Lỗi kết nối", errorMsg);
    });

    // Khi nhận message từ server
    connect(vpnClient, &VPNClient::messageReceived, this, [this](const QString& message) {
        logTextEdit->append(QString("[SERVER] %1").arg(message));

        // Parse thông tin IP từ server responses khác
        if (message.startsWith("VPN_IP|")) {
            QStringList parts = message.split("|");
            if (parts.size() >= 2) {
                currentVpnIP = parts[1];
                updateConnectionStatus();
                logTextEdit->append(QString("[INFO] VPN IP updated: %1").arg(currentVpnIP));
            }
        }
        else if (message.startsWith("STATUS|")) {
            // Parse status info nếu cần
            logTextEdit->append(QString("[INFO] Status: %1").arg(message.mid(7)));
        }
    });

    // Signal khi được cấp VPN IP
    connect(vpnClient, &VPNClient::vpnIPAssigned, this, [this](const QString& vpnIP) {
        currentVpnIP = vpnIP;
        updateConnectionStatus();
        logTextEdit->append(QString("[INFO] VPN IP assigned: %1").arg(vpnIP));
    });

    // Signal khi nhận status từ server
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

    QString username = usernameEdit->text().trimmed();
    QString password = passwordEdit->text().trimmed();

    if (username.isEmpty()) {
        QMessageBox::warning(this, "Lỗi", "Vui lòng nhập tên đăng nhập");
        return;
    }

    if (password.isEmpty()) {
        QMessageBox::warning(this, "Lỗi", "Vui lòng nhập mật khẩu");
        return;
    }

    // Disable button và hiện progress bar
    connectButton->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setRange(0, 0);

    logTextEdit->append("[INFO] Bắt đầu kết nối VPN...");
    logTextEdit->append(QString("[INFO] Connecting to server: %1:1194").arg("192.168.1.100"));

    // CHỈ gọi connectToServer MỘT LẦN duy nhất ở đây
    vpnClient->connectToServer("192.168.1.100", 1194, username, password);
}

void MainWindow::disconnectFromVPN()
{
    if (vpnClient) {
        vpnClient->disconnectFromServer();
    }

    isConnected = false;
    currentVpnIP.clear();
    updateConnectionStatus();
    progressBar->setVisible(false);
    connectButton->setEnabled(true);
    logTextEdit->append("Đã ngắt kết nối VPN!");

    // Cập nhật lại IP sau khi ngắt kết nối
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
        "© 2024 VPN Client");
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

        // Tăng dữ liệu fake
                totalDownload += (rand() % 1000 + 100);
                totalUpload += (rand() % 500 + 50);

                downloadLabel->setText(QString("↓ %1 KB").arg(totalDownload));
                uploadLabel->setText(QString("↑ %1 KB").arg(totalUpload));

        // Sử dụng QTime để tính thời gian kết nối chính xác
        if (connectionTimeStarted) {
            int totalSeconds = connectionStartTime.secsTo(QTime::currentTime());
            if (totalSeconds < 0) {
                // Xử lý trường hợp qua nửa đêm
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
        totalDownload = 0;  // Reset về 0
        totalUpload = 0;    // Reset về 0

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

    QList<QHostAddress> addresses = QNetworkInterface::allAddresses();
    for (const QHostAddress &address : addresses) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol &&
            address != QHostAddress::LocalHost) {
            localIP = address.toString();
            break;
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

            logTextEdit->append(QString("[INFO] IP công cộng hiện tại: %1").arg(currentPublicIP));
        }
    } else {
        publicIPLabel->setText("IP công cộng: Không xác định");
        logTextEdit->append("[WARN] Không thể lấy IP công cộng");
    }

    // Dọn dẹp an toàn
    disconnect(currentReply, nullptr, this, nullptr);
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

    // IP Information Group
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

    // Connection status group
    QGroupBox *statusGroup = new QGroupBox("Trạng thái kết nối");
    QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);

    statusLabel = new QLabel("Chưa kết nối");
    statusLabel->setStyleSheet("QLabel { font-weight: bold; font-size: 14px; color: red; }");
    statusLayout->addWidget(statusLabel);

    QHBoxLayout *statsLayout = new QHBoxLayout();
    downloadLabel = new QLabel("↓ 0 KB");
    uploadLabel = new QLabel("↑ 0 KB");
    connectionTimeLabel = new QLabel("Thời gian: 00:00:00");

    statsLayout->addWidget(downloadLabel);
    statsLayout->addWidget(uploadLabel);
    statsLayout->addStretch();
    statsLayout->addWidget(connectionTimeLabel);
    statusLayout->addLayout(statsLayout);

    mainLayout->addWidget(statusGroup);

    // Connection settings group
    QGroupBox *settingsGroup = new QGroupBox("Cài đặt kết nối");
    QGridLayout *settingsLayout = new QGridLayout(settingsGroup);

    settingsLayout->addWidget(new QLabel("Máy chủ:"), 0, 0);
    serverEdit = new QLineEdit("192.168.1.100:1194");
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

    // Control buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    connectButton = new QPushButton("Kết nối");
    connectButton->setStyleSheet(
        "QPushButton { font-weight: bold; padding: 10px 20px; font-size: 14px; }"
        "QPushButton:hover { background-color: #4CAF50; color: white; }"
    );
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::connectToVPN);
    buttonLayout->addWidget(connectButton);

    QPushButton *clearLogButton = new QPushButton("Xóa log");
    connect(clearLogButton, &QPushButton::clicked, this, &MainWindow::clearLog);
    buttonLayout->addWidget(clearLogButton);

    buttonLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // Progress bar
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);

    // Log area
    QGroupBox *logGroup = new QGroupBox("Nhật ký kết nối");
    QVBoxLayout *logLayout = new QVBoxLayout(logGroup);

    logTextEdit = new QTextEdit();
    logTextEdit->setMaximumHeight(120);
    logTextEdit->setReadOnly(true);
    logTextEdit->append("VPN Client Enhanced đã khởi động...");
    logTextEdit->append("Server: 192.168.1.100:1194 với cấp phát IP động");
    logLayout->addWidget(logTextEdit);

    mainLayout->addWidget(logGroup);

    // Menu bar
    QMenuBar *menuBar = this->menuBar();
    QMenu *fileMenu = menuBar->addMenu("Tệp");
    QAction *exitAction = fileMenu->addAction("Thoát");
    connect(exitAction, &QAction::triggered, this, &QWidget::close);

    QMenu *helpMenu = menuBar->addMenu("Trợ giúp");
    QAction *aboutAction = helpMenu->addAction("Về chương trình");
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);

    statusBar()->showMessage("Sẵn sàng kết nối tới VPN server với IP động");
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

    // Timer để cập nhật IP định kỳ
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
