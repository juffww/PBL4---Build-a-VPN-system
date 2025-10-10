#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <map>

class ConfigManager {
public:
    // Đọc và phân tích tệp cấu hình
    bool load(const std::string& filename);

    // Lấy giá trị dạng chuỗi
    std::string getString(const std::string& key, const std::string& defaultValue = "");

    // Lấy giá trị dạng số
    int getInt(const std::string& key, int defaultValue = 0);

private:
    std::map<std::string, std::string> configMap;
};

#endif // CONFIG_MANAGER_H