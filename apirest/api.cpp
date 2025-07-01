#include "crow.h"
#include "jwt.h"
#include <string>


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

std::string create_jwt(const std::string& username, const std::string& secret);

int main(){
    crow::SimpleApp app;

    CROW_ROUTE(app, "/login").methods("POST"_method)([](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        std::string username = body["username"].s();
        std::string password = body["password"].s();

	//usuario hardcodeado, tiene que conectarse a un DB
        if (username == "nico" && password == "1234") {
            std::string token = create_jwt(username, "mi_clave_secreta_123");

            crow::json::wvalue res;
            res["token"] = token;
            return crow::response{res};
        } else {
            return crow::response(401, "Unauthorized");
        }
    });

   CROW_ROUTE(app, "/archivos").methods("GET"_method)
   ([](const crow::request& req, crow::response& res) {
    crow::json::wvalue lista;

    lista["archivos"][0]["nombre"] = "informe.pdf";
    lista["archivos"][0]["tamano"] = 523000;
    lista["archivos"][0]["modificado"] = "2025-06-30 10:45";

    lista["archivos"][1]["nombre"] = "foto.jpg";
    lista["archivos"][1]["tamano"] = 32000;
    lista["archivos"][1]["modificado"] = "2025-06-28 18:10";

    lista["archivos"][2]["nombre"] = "planilla.xlsx";
    lista["archivos"][2]["tamano"] = 80200;
    lista["archivos"][2]["modificado"] = "2025-06-25 09:30";

    res.set_header("Content-Type", "application/json");
    res.write(lista.dump());
    res.end();
});

    CROW_ROUTE(app, "/subir").methods("POST"_method)
([](const crow::request& req, crow::response& res) {
    auto body = crow::json::load(req.body);
    if (!body) {
        res.code = 400;
        res.end("JSON inválido");
        return;
    }

    std::string nombre = body["nombre"].s();
    std::string path = body["path"].s();
    int size = body["size"].i();
    bool encryption = body["encryption"].b();

    // Usuario simulado (antes lo obtenías del JWT)
    std::string usuario = "nico";

    // Simulación: guardar en base de datos
    std::cout << "Subiendo archivo: " << nombre << " de " << size << " bytes por " << usuario << std::endl;

    crow::json::wvalue resp;
    resp["mensaje"] = "Archivo registrado exitosamente.";
    res.write(resp.dump());
    res.end();
});


    app.port(18080).multithreaded().run();
}

