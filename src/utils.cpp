#include "utils.h"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <iostream>

static std::mutex log_mutex;

std::string now_iso() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t = system_clock::to_time_t(now);
    std::tm tm;
    gmtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

void log_file_append(const std::string &path, const std::string &line) {
    std::lock_guard<std::mutex> guard(log_mutex);
    std::ofstream f(path, std::ios::app);
    if (f.is_open()) {
        f << line << std::endl;
    }
}

void log_alert(const std::string &line) {
    std::string out = now_iso() + " ALERT " + line;
    log_file_append("logs/alerts.log", out);
    std::cout << out << std::endl; // alerts also show on screen
}

void log_traffic(const std::string &line) {
    std::string out = now_iso() + " TRAFFIC " + line;
    log_file_append("logs/traffic.log", out);
}
