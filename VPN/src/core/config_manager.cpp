#include "config_manager.h"
#include <fstream>
#include <iostream>
#include <algorithm>

// (Thêm hàm 'trim' để xóa khoảng trắng ở đây)
std::string trim(const std::string& str) {
    const std::string whitespace = " \t";
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos) return "";
    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;
    return str.substr(strBegin, strRange);
}


bool ConfigManager::load(const std::string& filename) {
    std::ifstream configFile(filename);
    if (!configFile.is_open()) {
        std::cerr << "Lỗi: Không thể mở tệp cấu hình " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = trim(line.substr(0, delimiterPos));
            std::string value = trim(line.substr(delimiterPos + 1));
            if (!key.empty() && !value.empty()) {
                configMap[key] = value;
            }
        }
    }
    configFile.close();
    return true;
}

std::string ConfigManager::getString(const std::string& key, const std::string& defaultValue) {
    if (configMap.count(key)) {
        return configMap[key];
    }
    return defaultValue;
}

int ConfigManager::getInt(const std::string& key, int defaultValue) {
    if (configMap.count(key)) {
        try {
            return std::stoi(configMap[key]);
        } catch (const std::exception& e) {
            return defaultValue;
        }
    }
    return defaultValue;
}