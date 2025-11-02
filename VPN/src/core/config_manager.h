#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <map>

class ConfigManager {
public:
    bool load(const std::string& filename);

    std::string getString(const std::string& key, const std::string& defaultValue = "");

    int getInt(const std::string& key, int defaultValue = 0);

private:
    std::map<std::string, std::string> configMap;
};

#endif // CONFIG_MANAGER_H