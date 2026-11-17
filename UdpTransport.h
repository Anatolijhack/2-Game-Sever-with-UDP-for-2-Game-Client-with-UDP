#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>
#include <boost/asio.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "GameNet.h"       // PlayerId

// UDP-канал для того, что МОЖЕТ теряться: ввод (клиент -> сервер) и снимки (сервер -> клиент).
// Всё, что обязано дойти (вход, пати, лобби), остаётся на TCP+TLS.
//
// Как UDP привязывается к игроку:
//   1. При входе по TLS сервер создаёт UDP-сессию (create_session) и кладёт в конец Welcome:
//        [u16 udp_port][u32 sid][16 байт ключ]    (всё little-endian; канал зашифрован TLS)
//   2. Клиент шлёт по UDP датаграмму Bind. Сервер проверяет подпись, запоминает адрес отправителя
//      и отвечает BindOk. До этого момента по UDP ничего не отправляется (нет усиления).
//   3. Дальше ввод идёт по UDP, а снимки сервер шлёт по UDP, пока канал жив.
//      Датаграмма не влезла или канал молчит больше 5 секунд: send() вернёт false, и вызывающий
//      отправит пакет по TCP (запасной путь, игра продолжается).
//
// Формат датаграммы (little-endian):
//   [u8 MAGIC][u32 sid][u32 seq][u8 type][данные][8 байт подпись]
//   Подпись: HMAC-SHA256(ключ сессии, всё до подписи), обрезанный до 8 байт.
//   Типы клиента и сервера не пересекаются, поэтому отражённый пакет не принимается.
//
// Потоки: всё работает в игровом потоке (на game_io), блокировки не нужны.
// Датаграмма с неверной подписью, повтор, неизвестная сессия, мусор: молча отбрасываются.

namespace udpp {

    constexpr std::uint8_t     MAGIC = 0xA7;
    constexpr std::size_t      HEADER = 1 + 4 + 4 + 1;      // magic, sid, seq, type
    constexpr std::size_t      TAG = 8;
    constexpr std::size_t      MAX_DATAGRAM = 1200;          // безопасный размер без IP-фрагментации
    constexpr std::size_t      MAX_PAYLOAD = MAX_DATAGRAM - HEADER - TAG;     // 1182
    constexpr std::size_t      KEY_LEN = 16;
    constexpr std::size_t      INPUT_CMD_LEN = 10;           // u32 seq, u8 flags, u8 nums, i16 aimX, i16 aimY
    constexpr std::size_t      MAX_INPUT_CMDS = 8;

    // клиент -> сервер
    constexpr std::uint8_t C2S_BIND = 0x01;     // без данных
    constexpr std::uint8_t C2S_INPUT = 0x02;    // [u8 n] n x { 10 байт команды ввода }: последние команды, старые первыми

    // сервер -> клиент
    constexpr std::uint8_t S2C_BIND_OK = 0x81;  // без данных
    constexpr std::uint8_t S2C_DATA = 0x82;     // данные: тот же пакет, что ушёл бы по TCP (например, Snapshot)

} // namespace udpp

class UdpTransport
{
    using udp = boost::asio::ip::udp;
    using clock = std::chrono::steady_clock;

public:
    // Что клиент получает в Welcome
    struct Info
    {
        std::uint16_t port = 0;
        std::uint32_t sid = 0;
        std::array<std::uint8_t, udpp::KEY_LEN> key{};
    };

    // on_packet: куда отдавать принятый ввод. Он получает ровно такой пакет, какой пришёл бы по TCP:
    // [tcp_input_type][10 байт команды]. Поэтому разбор и проверки остаются в одном месте (GameHost::on_packet).
    using PacketHandler = std::function<void(PlayerId, const std::uint8_t*, std::size_t)>;

    UdpTransport(boost::asio::io_context& io, std::uint16_t port,
        PacketHandler on_packet, std::uint8_t tcp_input_type)
        : socket_(io, udp::endpoint(udp::v4(), port)),
        port_(port), on_packet_(std::move(on_packet)), tcp_input_type_(tcp_input_type)
    {
        boost::system::error_code ec;
        socket_.non_blocking(true, ec);        // send_to не должен блокировать игровой поток
        receive();
    }

    void close()
    {
        boost::system::error_code ec;
        socket_.close(ec);
    }

    // ---------------- сессии (вызывать из GameHost::on_join / on_disconnect) ----------------

    Info create_session(PlayerId conn)
    {
        destroy_session(conn);                 // старая сессия того же соединения (на всякий случай)

        Session s;
        s.conn = conn;
        RAND_bytes(s.key.data(), static_cast<int>(s.key.size()));

        std::uint32_t sid = 0;
        do { RAND_bytes(reinterpret_cast<unsigned char*>(&sid), 4); } while (sid == 0 || by_sid_.count(sid));
        s.sid = sid;

        Info info;
        info.port = port_;
        info.sid = sid;
        info.key = s.key;

        by_sid_[sid] = std::move(s);
        sid_of_[conn] = sid;
        return info;
    }

    void destroy_session(PlayerId conn)
    {
        auto it = sid_of_.find(conn);
        if (it == sid_of_.end()) return;
        by_sid_.erase(it->second);
        sid_of_.erase(it);
    }

    // ---------------- отправка ----------------

    // true, если пакет ушёл по UDP. false: нужно отправить его по TCP.
    // Размер каждого пакета замеряется здесь даже когда UDP ещё не привязан (статистика для урезания).
    bool send(PlayerId conn, const std::vector<std::uint8_t>& payload)
    {
        ++stats_.offered;
        stats_.max_payload = std::max(stats_.max_payload, payload.size());
        const bool big = payload.size() > udpp::MAX_PAYLOAD;
        if (big) ++stats_.too_big;

        auto sit = sid_of_.find(conn);
        if (sit == sid_of_.end()) return false;

        Session& s = by_sid_[sit->second];
        const auto now = clock::now();
        if (!s.bound || now - s.last_rx > std::chrono::seconds(5)) { ++stats_.not_bound; return false; }
        if (big) return false;

        send_raw(s, udpp::S2C_DATA, payload.data(), payload.size());
        ++stats_.tx;
        return true;
    }

    // Строка для лога; счётчики обнуляются
    std::string report_and_reset()
    {
        const std::string line =
            "[udp] sessions " + std::to_string(by_sid_.size()) +
            " | rx " + std::to_string(stats_.rx) + " tx " + std::to_string(stats_.tx) +
            " | input cmds " + std::to_string(stats_.input_cmds) + " dup " + std::to_string(stats_.input_dup) +
            " | drop: format " + std::to_string(stats_.drop_format) +
            " unknown " + std::to_string(stats_.drop_unknown) +
            " auth " + std::to_string(stats_.drop_auth) +
            " replay " + std::to_string(stats_.drop_replay) +
            " rate " + std::to_string(stats_.drop_rate) +
            " | snapshots offered " + std::to_string(stats_.offered) +
            " not-bound " + std::to_string(stats_.not_bound) +
            " too-big " + std::to_string(stats_.too_big) +
            " max " + std::to_string(stats_.max_payload) + " B (limit " + std::to_string(udpp::MAX_PAYLOAD) + ")";
        stats_ = Stats{};
        return line;
    }

private:
    struct ReplayWindow
    {
        std::uint32_t highest = 0;
        std::uint64_t bits = 0;            // бит i = получен номер (highest - i)
        bool initialized = false;

        // true, если номер новый (и запоминается). false: повтор или слишком старый.
        bool accept(std::uint32_t seq)
        {
            if (!initialized) { initialized = true; highest = seq; bits = 1; return true; }

            if (seq > highest)
            {
                const std::uint32_t shift = seq - highest;
                bits = (shift >= 64) ? 0 : (bits << shift);
                bits |= 1;
                highest = seq;
                return true;
            }

            const std::uint32_t diff = highest - seq;
            if (diff >= 64) return false;                    // старше окна
            const std::uint64_t mask = 1ull << diff;
            if (bits & mask) return false;                   // уже было
            bits |= mask;
            return true;
        }
    };

    struct Session
    {
        PlayerId conn = 0;
        std::uint32_t sid = 0;
        std::array<std::uint8_t, udpp::KEY_LEN> key{};
        udp::endpoint ep;
        bool bound = false;
        ReplayWindow window;
        std::uint32_t send_seq = 0;
        std::uint32_t last_input_seq = 0;      // самая новая команда ввода, уже отданная игре
        clock::time_point last_rx{};
        clock::time_point rate_start{};
        int rate_count = 0;
    };

    struct Stats
    {
        std::uint64_t rx = 0, tx = 0;
        std::uint64_t drop_format = 0, drop_unknown = 0, drop_auth = 0, drop_replay = 0, drop_rate = 0;
        std::uint64_t input_cmds = 0, input_dup = 0;
        std::uint64_t offered = 0, not_bound = 0, too_big = 0;
        std::size_t max_payload = 0;
    };

    // ---------------- приём ----------------

    void receive()
    {
        socket_.async_receive_from(boost::asio::buffer(buf_), from_,
            [this](const boost::system::error_code& ec, std::size_t n)
            {
                if (ec == boost::asio::error::operation_aborted ||
                    ec == boost::asio::error::bad_descriptor) return;      // сокет закрыт

                // Любая другая ошибка (на Windows это, например, ICMP "порт недоступен" после отправки
                // клиенту, которого уже нет) не должна останавливать приём.
                if (!ec) handle(n);
                receive();
            });
    }

    void handle(std::size_t n)
    {
        ++stats_.rx;

        // 1. Форма: длина, магический байт
        if (n < udpp::HEADER + udpp::TAG || n > udpp::MAX_DATAGRAM || buf_[0] != udpp::MAGIC)
        {
            ++stats_.drop_format;
            return;
        }

        // 2. Сессия по идентификатору (адрес отправителя НЕ доверенный)
        const std::uint32_t sid = rd32(&buf_[1]);
        auto it = by_sid_.find(sid);
        if (it == by_sid_.end()) { ++stats_.drop_unknown; return; }
        Session& s = it->second;

        // 3. Подпись. Окно повторов обновляется только после неё, иначе его можно отравить поддельными пакетами.
        if (!verify(s.key, buf_.data(), n)) { ++stats_.drop_auth; return; }

        // 4. Повтор или слишком старый номер
        const std::uint32_t seq = rd32(&buf_[5]);
        if (!s.window.accept(seq)) { ++stats_.drop_replay; return; }

        // 5. Частота (клиент шлёт около 30 датаграмм в секунду; лимит с большим запасом)
        const auto now = clock::now();
        if (now - s.rate_start >= std::chrono::seconds(1)) { s.rate_start = now; s.rate_count = 0; }
        if (++s.rate_count > 200) { ++stats_.drop_rate; return; }

        // Подпись верна: адрес можно запомнить (клиент мог сменить сеть)
        s.ep = from_;
        s.last_rx = now;

        const std::uint8_t type = buf_[9];
        const std::uint8_t* payload = buf_.data() + udpp::HEADER;
        const std::size_t plen = n - udpp::HEADER - udpp::TAG;

        switch (type)
        {
        case udpp::C2S_BIND:
            if (plen != 0) { ++stats_.drop_format; return; }
            s.bound = true;
            send_raw(s, udpp::S2C_BIND_OK, nullptr, 0);
            break;

        case udpp::C2S_INPUT:
            if (!s.bound) return;                             // сначала Bind
            handle_input(s, payload, plen);
            break;

        default:
            ++stats_.drop_format;
        }
    }

    // Датаграмма несёт последние команды ввода (старые первыми). Игре отдаём только новые.
    void handle_input(Session& s, const std::uint8_t* p, std::size_t len)
    {
        if (len < 1) { ++stats_.drop_format; return; }
        const std::size_t n = p[0];
        if (n == 0 || n > udpp::MAX_INPUT_CMDS || len != 1 + n * udpp::INPUT_CMD_LEN)
        {
            ++stats_.drop_format;
            return;
        }

        for (std::size_t i = 0; i < n; ++i)
        {
            const std::uint8_t* cmd = p + 1 + i * udpp::INPUT_CMD_LEN;
            const std::uint32_t seq = rd32(cmd);

            if (seq <= s.last_input_seq) { ++stats_.input_dup; continue; }   // уже отдавали (повтор из-за избыточности)
            s.last_input_seq = seq;
            ++stats_.input_cmds;

            // Тот же пакет, что пришёл бы по TCP: дальше его разбирает GameHost::on_packet
            std::array<std::uint8_t, 1 + udpp::INPUT_CMD_LEN> pkt;
            pkt[0] = tcp_input_type_;
            std::memcpy(&pkt[1], cmd, udpp::INPUT_CMD_LEN);
            on_packet_(s.conn, pkt.data(), pkt.size());
        }
    }

    // ---------------- отправка ----------------

    void send_raw(Session& s, std::uint8_t type, const std::uint8_t* payload, std::size_t len)
    {
        if (len > udpp::MAX_PAYLOAD) return;

        std::array<std::uint8_t, udpp::MAX_DATAGRAM> out;
        std::size_t n = 0;
        out[n++] = udpp::MAGIC;
        wr32(&out[n], s.sid);         n += 4;
        wr32(&out[n], ++s.send_seq);  n += 4;
        out[n++] = type;
        if (len) { std::memcpy(&out[n], payload, len); n += len; }

        sign(s.key, out.data(), n, &out[n]);
        n += udpp::TAG;

        // Ошибки (в том числе would_block) игнорируем: UDP не гарантирует доставку, снимок заменит следующий
        boost::system::error_code ec;
        socket_.send_to(boost::asio::buffer(out.data(), n), s.ep, 0, ec);
    }

    // ---------------- подпись и байты ----------------

    static void sign(const std::array<std::uint8_t, udpp::KEY_LEN>& key,
        const std::uint8_t* data, std::size_t len, std::uint8_t* tag_out)
    {   
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data, len, md, &mdlen);
        std::memcpy(tag_out, md, udpp::TAG);
    }

    static bool verify(const std::array<std::uint8_t, udpp::KEY_LEN>& key,
        const std::uint8_t* data, std::size_t n)
    {
        std::uint8_t expect[udpp::TAG];
        sign(key, data, n - udpp::TAG, expect);
        return CRYPTO_memcmp(expect, data + n - udpp::TAG, udpp::TAG) == 0;     // сравнение за постоянное время
    }

    static std::uint32_t rd32(const std::uint8_t* p)
    {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
            (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
    }

    static void wr32(std::uint8_t* p, std::uint32_t v)
    {
        p[0] = static_cast<std::uint8_t>(v & 0xFF);
        p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
        p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
    }

    udp::socket socket_;
    std::uint16_t port_;
    PacketHandler on_packet_;
    std::uint8_t tcp_input_type_;

    std::array<std::uint8_t, 1500> buf_{};
    udp::endpoint from_;

    std::unordered_map<std::uint32_t, Session> by_sid_;     // sid -> сессия
    std::unordered_map<PlayerId, std::uint32_t> sid_of_;    // соединение -> sid
    Stats stats_;
};