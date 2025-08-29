#pragma once
#include <string>

class BpfError : public std::exception {
private:
    std::string message;

public:
    explicit BpfError(const std::string& msg)
        : message("BPF: " + msg)
    {
    }

    const char* what() const noexcept override
    {
        return message.c_str();
    }
};