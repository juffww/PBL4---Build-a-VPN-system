// src/api/web_server.cpp
#include <crow.h>
#include <nlohmann/json.hpp>
#include "client_manager.h"

using json = nlohmann::json;

class WebServer {
private:
    crow::SimpleApp app_;
    std::unique_ptr<ClientManager> client_manager_;
    
public:
    WebServer() : client_manager_(std::make_unique<ClientManager>()) {
        SetupRoutes();
    }
    
    void Start(int port = 8080) {
        app_.port(port).multithreaded().run();
    }
    
private:
    void SetupRoutes() {
        // Serve static files
        CROW_ROUTE(app_, "/")
        ([](const crow::request& req) {
            return crow::load_text("static/dashboard.html");
        });
        
        // API: Get all clients
        CROW_ROUTE(app_, "/api/clients").methods("GET"_method)
        ([this](const crow::request& req) {
            auto clients = client_manager_->GetAllClients();
            json response = json::array();
            
            for (const auto& client : clients) {
                response.push_back({
                    {"id", client.id},
                    {"name", client.name},
                    {"ip", client.ip_address},
                    {"status", client.is_connected ? "Connected" : "Disconnected"},
                    {"bytes_sent", client.bytes_sent},
                    {"bytes_received", client.bytes_received},
                    {"last_seen", client.last_seen}
                });
            }
            
            return crow::response(200, response.dump());
        });
        
        // API: Add new client
        CROW_ROUTE(app_, "/api/clients").methods("POST"_method)
        ([this](const crow::request& req) {
            try {
                auto body = json::parse(req.body);
                std::string name = body["name"];
                
                auto client = client_manager_->CreateClient(name);
                if (client.has_value()) {
                    json response = {
                        {"id", client->id},
                        {"name", client->name},
                        {"config", client->config}
                    };
                    return crow::response(201, response.dump());
                }
                
                return crow::response(400, "Failed to create client");
            } catch (const std::exception& e) {
                return crow::response(400, "Invalid request body");
            }
        });
        
        // API: Delete client
        CROW_ROUTE(app_, "/api/clients/<int>").methods("DELETE"_method)
        ([this](const crow::request& req, int client_id) {
            if (client_manager_->DeleteClient(client_id)) {
                return crow::response(200, "Client deleted successfully");
            }
            return crow::response(404, "Client not found");
        });
        
        // API: Get server stats
        CROW_ROUTE(app_, "/api/stats").methods("GET"_method)
        ([this](const crow::request& req) {
            auto stats = client_manager_->GetServerStats();
            json response = {
                {"total_clients", stats.total_clients},
                {"active_connections", stats.active_connections},
                {"total_bytes_sent", stats.total_bytes_sent},
                {"total_bytes_received", stats.total_bytes_received},
                {"uptime", stats.uptime_seconds}
            };
            return crow::response(200, response.dump());
        });
    }
};

void VPNServer::WebServerLoop() {
    WebServer web_server;
    std::cout << "Starting web dashboard on port 8080" << std::endl;
    web_server.Start(8080);
}