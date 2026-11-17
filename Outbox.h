#pragma once
#include <fstream>
#include <mutex>
#include <vector>
#include <cstdio>
#include "ResultSink.h"

class Outbox
{
public:
    explicit Outbox(std::string path) : path_(std::move(path)) {}

    void append(const MatchResultRecord& r)
    {
        std::lock_guard<std::mutex> lk(m_);
        std::ofstream f(path_, std::ios::app);
        f << to_line(r) << "\n";
        f.flush();
    }

    // Пробует отправить всё. try_save: true = записано (или уже было).
    template <class F>
    void flush(F&& try_save)
    {
        std::lock_guard<std::mutex> lk(m_);
        std::ifstream in(path_);
        if (!in) return;

        std::vector<std::string> keep;
        std::string line;
        while (std::getline(in, line))
        {
            if (line.empty()) continue;
            MatchResultRecord r;
            if (!from_line(line, r)) { std::cerr << "[outbox] bad line dropped\n"; continue; }
            if (!try_save(r)) keep.push_back(line);
        }
        in.close();

        if (keep.empty()) { std::remove(path_.c_str()); return; }
        std::ofstream out(path_, std::ios::trunc);
        for (auto& l : keep) out << l << "\n";
    }

private:
    std::string path_;
    std::mutex m_;
};