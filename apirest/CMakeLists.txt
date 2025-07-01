cmake_minimum_required(VERSION 3.10)
project(MiAPI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Incluir rutas
include_directories(
	$ENV{HOME}/utils/Crow/include
	$ENV{HOME}/utils/jwt-cpp/include/jwt-cpp
	$ENV{HOME}/utils/jwt-cpp/include
	$ENV{HOME}/utils
	$ENV{HOME}/utils/asio/asio/include
)
find_package(OpenSSL REQUIRED)

# Agregar ejecutable
add_executable(app api.cpp)

# Linkear
target_link_libraries(app pthread OpenSSL::SSL OpenSSL::Crypto)

