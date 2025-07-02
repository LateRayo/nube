#include "crow.h"
#include "jwt.h"
#include <mysql.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Configuración de base de datos
struct DBConfig {
    std::string host = "localhost";
    std::string user = "root";
    std::string password = "";
    std::string database = "nube_local";
    int port = 3306;
};

// Configuración SFTP
struct SFTPConfig {
    std::string host = "localhost";
    std::string user = "termux";
    std::string password = "";
    int port = 2222;
    std::string base_path = "/data/data/com.termux/files/home/nube_archivos/";
};

class DatabaseManager {
private:
    MYSQL* connection;
    DBConfig config;
    
public:
    DatabaseManager(const DBConfig& cfg) : config(cfg), connection(nullptr) {}
    
    bool connect() {
        connection = mysql_init(nullptr);
        if (!connection) {
            std::cerr << "Error inicializando MySQL" << std::endl;
            return false;
        }
        
        connection = mysql_real_connect(connection, 
            config.host.c_str(), config.user.c_str(), 
            config.password.c_str(), config.database.c_str(),
            config.port, nullptr, 0);
            
        if (!connection) {
            std::cerr << "Error conectando a la base de datos: " << mysql_error(connection) << std::endl;
            return false;
        }
        
        std::cout << "Conectado a MariaDB exitosamente" << std::endl;
        return true;
    }
    
    bool insertFile(const std::string& name, const std::string& path, 
                   int size, const std::string& user, bool encryption) {
        if (!connection) return false;
        
        std::string query = "INSERT INTO archivos (name, path, size, user_that_uploaded, encryption) VALUES (?, ?, ?, ?, ?)";
        MYSQL_STMT* stmt = mysql_stmt_init(connection);
        
        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            std::cerr << "Error preparando statement: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }
        
        MYSQL_BIND bind[5];
        memset(bind, 0, sizeof(bind));
        
        // name
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (void*)name.c_str();
        bind[0].buffer_length = name.length();
        
        // path
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = (void*)path.c_str();
        bind[1].buffer_length = path.length();
        
        // size
        bind[2].buffer_type = MYSQL_TYPE_LONG;
        bind[2].buffer = &size;
        
        // user
        bind[3].buffer_type = MYSQL_TYPE_STRING;
        bind[3].buffer = (void*)user.c_str();
        bind[3].buffer_length = user.length();
        
        // encryption
        bind[4].buffer_type = MYSQL_TYPE_TINY;
        bind[4].buffer = &encryption;
        
        mysql_stmt_bind_param(stmt, bind);
        
        bool success = mysql_stmt_execute(stmt) == 0;
        if (!success) {
            std::cerr << "Error ejecutando insert: " << mysql_stmt_error(stmt) << std::endl;
        }
        
        mysql_stmt_close(stmt);
        return success;
    }
    
    bool addModification(int archivo_id, const std::string& usuario, const std::string& descripcion) {
        if (!connection) return false;
        
        std::string query = "INSERT INTO modificaciones (archivo_id, usuario, descripcion) VALUES (?, ?, ?)";
        MYSQL_STMT* stmt = mysql_stmt_init(connection);
        
        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            mysql_stmt_close(stmt);
            return false;
        }
        
        MYSQL_BIND bind[3];
        memset(bind, 0, sizeof(bind));
        
        bind[0].buffer_type = MYSQL_TYPE_LONG;
        bind[0].buffer = &archivo_id;
        
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = (void*)usuario.c_str();
        bind[1].buffer_length = usuario.length();
        
        bind[2].buffer_type = MYSQL_TYPE_STRING;
        bind[2].buffer = (void*)descripcion.c_str();
        bind[2].buffer_length = descripcion.length();
        
        mysql_stmt_bind_param(stmt, bind);
        bool success = mysql_stmt_execute(stmt) == 0;
        mysql_stmt_close(stmt);
        return success;
    }
    
    ~DatabaseManager() {
        if (connection) {
            mysql_close(connection);
        }
    }
};

class SFTPManager {
private:
    SFTPConfig config;
    LIBSSH2_SESSION* session;
    LIBSSH2_SFTP* sftp_session;
    int sock;
    
public:
    SFTPManager(const SFTPConfig& cfg) : config(cfg), session(nullptr), sftp_session(nullptr), sock(-1) {}
    
    bool connect() {
        // Inicializar libssh2
        if (libssh2_init(0) != 0) {
            std::cerr << "Error inicializando libssh2" << std::endl;
            return false;
        }
        
        // Crear socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            std::cerr << "Error creando socket" << std::endl;
            return false;
        }
        
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(config.port);
        sin.sin_addr.s_addr = inet_addr(config.host.c_str());
        
        if (::connect(sock, (struct sockaddr*)&sin, sizeof(struct sockaddr_in)) != 0) {
            std::cerr << "Error conectando socket SFTP" << std::endl;
            return false;
        }
        
        // Crear sesión SSH2
        session = libssh2_session_init();
        if (!session) {
            std::cerr << "Error creando sesión SSH2" << std::endl;
            return false;
        }
        
        if (libssh2_session_handshake(session, sock)) {
            std::cerr << "Error en handshake SSH2" << std::endl;
            return false;
        }
        
        // Autenticar
        if (libssh2_userauth_password(session, config.user.c_str(), config.password.c_str())) {
            std::cerr << "Error autenticando SFTP" << std::endl;
            return false;
        }
        
        // Inicializar SFTP
        sftp_session = libssh2_sftp_init(session);
        if (!sftp_session) {
            std::cerr << "Error inicializando sesión SFTP" << std::endl;
            return false;
        }
        
        std::cout << "Conectado a SFTP exitosamente" << std::endl;
        return true;
    }
    
    bool uploadFile(const std::string& local_path, const std::string& remote_filename) {
        if (!sftp_session) return false;
        
        std::string remote_path = config.base_path + remote_filename;
        
        // Abrir archivo local para lectura
        std::ifstream local_file(local_path, std::ios::binary);
        if (!local_file.is_open()) {
            std::cerr << "Error abriendo archivo local: " << local_path << std::endl;
            return false;
        }
        
        // Crear archivo remoto
        LIBSSH2_SFTP_HANDLE* sftp_handle = libssh2_sftp_open(sftp_session, remote_path.c_str(),
            LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC,
            LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
            
        if (!sftp_handle) {
            std::cerr << "Error creando archivo remoto: " << remote_path << std::endl;
            return false;
        }
        
        // Transferir archivo
        char buffer[1024];
        size_t bytes_written = 0;
        
        while (local_file.read(buffer, sizeof(buffer)) || local_file.gcount() > 0) {
            size_t bytes_read = local_file.gcount();
            ssize_t rc = libssh2_sftp_write(sftp_handle, buffer, bytes_read);
            
            if (rc < 0) {
                std::cerr << "Error escribiendo al archivo remoto" << std::endl;
                libssh2_sftp_close(sftp_handle);
                return false;
            }
            bytes_written += rc;
        }
        
        libssh2_sftp_close(sftp_handle);
        local_file.close();
        
        std::cout << "Archivo subido exitosamente: " << bytes_written << " bytes" << std::endl;
        return true;
    }
    
    ~SFTPManager() {
        if (sftp_session) {
            libssh2_sftp_shutdown(sftp_session);
        }
        if (session) {
            libssh2_session_disconnect(session, "Desconectando");
            libssh2_session_free(session);
        }
        if (sock != -1) {
            close(sock);
        }
        libssh2_exit();
    }
};

// Función para crear JWT (tu código existente)
std::string create_jwt(const std::string& username, const std::string& secret) {
    using namespace std::chrono;
    auto token = jwt::create()
        .set_issuer("tu_empresa")
        .set_type("JWS")
        .set_subject(username)
        .set_issued_at(system_clock::now())
        .set_expires_at(system_clock::now() + minutes{30})
        .sign(jwt::algorithm::hs256{secret});
    return token;
}

// Función para validar JWT
bool validate_jwt(const std::string& token, const std::string& secret, std::string& username) {
    try {
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret})
            .with_issuer("tu_empresa");
        
        auto decoded = jwt::decode(token);
        verifier.verify(decoded);
        username = decoded.get_subject();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error validando JWT: " << e.what() << std::endl;
        return false;
    }
}

int main() {
    crow::SimpleApp app;
    
    // Inicializar managers
    DBConfig db_config;
    SFTPConfig sftp_config;
    
    DatabaseManager db(db_config);
    SFTPManager sftp(sftp_config);
    
    // Conectar a servicios
    if (!db.connect()) {
        std::cerr << "No se pudo conectar a la base de datos" << std::endl;
        return 1;
    }
    
    if (!sftp.connect()) {
        std::cerr << "No se pudo conectar a SFTP" << std::endl;
        return 1;
    }
    
    // Endpoint de login (tu código existente)
    CROW_ROUTE(app, "/login").methods("POST"_method)([](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");
        
        std::string username = body["username"].s();
        std::string password = body["password"].s();
        
        // Usuario hardcodeado por ahora
        if (username == "nico" && password == "1234") {
            std::string token = create_jwt(username, "mi_clave_secreta_123");
            crow::json::wvalue res;
            res["token"] = token;
            return crow::response{res};
        } else {
            return crow::response(401, "Unauthorized");
        }
    });
    
    // Endpoint para subir archivos con SFTP y DB
    CROW_ROUTE(app, "/upload").methods("POST"_method)
    ([&db, &sftp](const crow::request& req) {
        // Validar JWT
        std::string auth_header = req.get_header_value("Authorization");
        if (auth_header.empty() || auth_header.substr(0, 7) != "Bearer ") {
            return crow::response(401, "Token requerido");
        }
        
        std::string token = auth_header.substr(7);
        std::string username;
        if (!validate_jwt(token, "mi_clave_secreta_123", username)) {
            return crow::response(401, "Token inválido");
        }
        
        // Parsear JSON
        auto body = crow::json::load(req.body);
        if (!body) {
            return crow::response(400, "JSON inválido");
        }
        
        std::string nombre = body["nombre"].s();
        std::string local_path = body["local_path"].s(); // Ruta del archivo en el dispositivo
        bool encryption = body["encryption"].b();
        
        // Verificar que el archivo local existe
        if (!std::filesystem::exists(local_path)) {
            return crow::response(400, "Archivo local no encontrado");
        }
        
        // Obtener tamaño del archivo
        auto file_size = std::filesystem::file_size(local_path);
        
        // Subir archivo por SFTP
        if (!sftp.uploadFile(local_path, nombre)) {
            return crow::response(500, "Error subiendo archivo por SFTP");
        }
        
        // Registrar en base de datos
        std::string remote_path = "/nube_archivos/" + nombre;
        if (!db.insertFile(nombre, remote_path, file_size, username, encryption)) {
            return crow::response(500, "Error registrando archivo en DB");
        }
        
        // Registrar modificación
        // Nota: Necesitarías obtener el ID del archivo insertado para esto
        // db.addModification(archivo_id, username, "Archivo subido");
        
        crow::json::wvalue resp;
        resp["mensaje"] = "Archivo subido exitosamente";
        resp["nombre"] = nombre;
        resp["tamaño"] = (int)file_size;
        resp["usuario"] = username;
        
        return crow::response{resp};
    });
    
    // Endpoint para listar archivos (mejorado)
    CROW_ROUTE(app, "/archivos").methods("GET"_method)
    ([](const crow::request& req) {
        // Validar JWT
        std::string auth_header = req.get_header_value("Authorization");
        if (auth_header.empty() || auth_header.substr(0, 7) != "Bearer ") {
            return crow::response(401, "Token requerido");
        }
        
        std::string token = auth_header.substr(7);
        std::string username;
        if (!validate_jwt(token, "mi_clave_secreta_123", username)) {
            return crow::response(401, "Token inválido");
        }
        
        // Por ahora devolver datos de prueba
        // Aquí deberías consultar la base de datos
        crow::json::wvalue lista;
        lista["archivos"][0]["nombre"] = "informe.pdf";
        lista["archivos"][0]["tamano"] = 523000;
        lista["archivos"][0]["modificado"] = "2025-06-30 10:45";
        lista["archivos"][0]["usuario"] = "nico";
        
        return crow::response{lista};
    });
    
    std::cout << "Servidor iniciando en puerto 8080..." << std::endl;
    app.port(8080).multithreaded().run();
    
    return 0;
}
