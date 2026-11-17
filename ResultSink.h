#pragma once
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>


struct MatchPlayerResult
{
    int           user_id = 0;
    std::uint16_t points = 0;
};

struct MatchResultRecord
{
    std::string   match_guid;          // создаётся при старте матча
    std::int64_t  started_unix = 0;
    std::int64_t  ended_unix = 0;
    std::uint16_t wave = 0;
    std::uint32_t score = 0;
    std::vector<MatchPlayerResult> players;
};

struct IResultSink
{
    virtual void save(MatchResultRecord r) = 0;
    virtual ~IResultSink() = default;
};

// Для проверки без базы: просто печатает
struct LogSink : IResultSink
{
    void save(MatchResultRecord r) override
    {
        std::cout << "[result] " << r.match_guid
            << " wave=" << r.wave << " score=" << r.score
            << " duration=" << (r.ended_unix - r.started_unix) << "s players:";
        for (const auto& p : r.players)
            std::cout << " (user " << p.user_id << ": " << p.points << ")";
        std::cout << std::endl;
    }
};

inline std::string to_line(const MatchResultRecord& r)
{
    std::string s = r.match_guid + ";" + std::to_string(r.started_unix) + ";" +
        std::to_string(r.ended_unix) + ";" + std::to_string(r.wave) + ";" +
        std::to_string(r.score) + ";";
    for (const auto& p : r.players)
        s += std::to_string(p.user_id) + ":" + std::to_string(p.points) + ",";
    return s;
}

inline bool from_line(const std::string& line, MatchResultRecord& r)
{
    try
    {
        std::vector<std::string> f;
        size_t pos = 0, next;
        while ((next = line.find(';', pos)) != std::string::npos)
        {
            f.push_back(line.substr(pos, next - pos)); pos = next + 1;
        }
        f.push_back(line.substr(pos));
        if (f.size() < 6) return false;

        r = MatchResultRecord{};
        r.match_guid = f[0];
        r.started_unix = std::stoll(f[1]);
        r.ended_unix = std::stoll(f[2]);
        r.wave = static_cast<std::uint16_t>(std::stoi(f[3]));
        r.score = static_cast<std::uint32_t>(std::stoul(f[4]));

        size_t a = 0;
        while (a < f[5].size())
        {
            size_t comma = f[5].find(',', a);
            if (comma == std::string::npos) break;
            std::string item = f[5].substr(a, comma - a);
            size_t colon = item.find(':');
            if (colon != std::string::npos)
                r.players.push_back({ std::stoi(item.substr(0, colon)),
                    static_cast<std::uint16_t>(std::stoi(item.substr(colon + 1))) });
            a = comma + 1;
        }
        return r.match_guid.size() == 32;
    }
    catch (...) { return false; }
}