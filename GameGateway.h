#pragma once
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>
#include <boost/asio.hpp>
#include "ChatService.h"
#include "GameNet.h"
#include "Protocol.h"
#include "Session.h"
#include "UdpTransport.h"

class GameGateway : public IGameNet {
public:

    std::string udp_report() { return udp_->report_and_reset(); }
    GameGateway(boost::asio::io_context& game_io, ChatService& auth)
        : game_io_(game_io), auth_(auth), udp_(std::make_unique<UdpTransport>(
            game_io,
            8767,
            [this](PlayerId id, const uint8_t* data, size_t size) {
                boost::asio::post(game_io_, [this, id,
                    packet = std::vector<uint8_t>(data, data + size)]() {
                        if (game_) {
                            game_->on_packet(id, packet.data(), packet.size());
                        }
                    });
            },
            proto::C2S_INPUT)) 
    {
        arm_stats();
    }

    void set_game(IGameHandler& game) { game_ = &game; }

    // ===== вызывается из потока сессии =====
    void on_frame(const std::shared_ptr<Session>& s, std::string payload)
    {
        if (payload.empty()) return;

        if (s->game_id == 0)                       // ещё не вошёл: допустим один Hello с токеном
        {
            if (s->game_joining || static_cast<std::uint8_t>(payload[0]) != proto::C2S_HELLO)
            {
                s->raw_close(KICK_PROTOCOL);
                return;
            }
            s->game_joining = true;

            if (payload.size() < 2 ||
                static_cast<std::uint8_t>(payload[1]) != proto::PROTOCOL_VERSION)
            {
                s->raw_close(KICK_VERSION);
                return;
            }

            const std::string token = payload.substr(2, 128);
            const bool queued = auth_.verify_token(token,
                [this, s](std::optional<ChatService::TokenIdentity> id)      // рабочий поток
                {
                    s->ws_post([this, s, id]() { finish_join(s, id); });     // назад в поток сессии
                });

            if (!queued) s->raw_close(KICK_BUSY);
            return;
        }

        const PlayerId id = s->game_id;
        boost::asio::post(game_io_, [this, id, p = std::move(payload)]()
            {
                game_->on_packet(id, reinterpret_cast<const std::uint8_t*>(p.data()), p.size());
            });
    }

    // вызывается из ~Session (любой поток)
    void on_close(PlayerId id)
    {
        boost::asio::post(game_io_, [this, id]()
            {
                udp_->destroy_session(id);
                sessions_.erase(id);
                game_->on_disconnect(id);
                
            });
    }

    void arm_stats()
    {
        stat_timer_.expires_after(std::chrono::seconds(10));
        stat_timer_.async_wait([this](const boost::system::error_code& ec)
            {
                if (ec) return;
                std::cout << udp_->report_and_reset() << std::endl;
                arm_stats();
            });
    }

    // ===== IGameNet: вызывается из игрового потока =====
    void send(
        PlayerId id,
        const std::vector<std::uint8_t>& packet,
        bool reliable
    ) override
    {
        // Ненадёжные пакеты сначала пробуем отправить через UDP.
        if (!reliable && udp_->send(id, packet)) {
            return;
        }

        // UDP недоступен или пакет не помещается — отправляем по TCP.
        auto it = sessions_.find(id);
        if (it == sessions_.end()) return;

        auto s = it->second.lock();
        if (!s) return;

        std::string data(packet.begin(), packet.end());

        s->ws_post([s, data = std::move(data), reliable]() {
            s->send_raw(data, reliable);
            });
    }

    void disconnect(PlayerId id, std::uint8_t reason) override
    {  
        auto it = sessions_.find(id);
        if (it == sessions_.end()) return;
        if (auto s = it->second.lock())
        {
            std::cout << "disconnect id=" << id << " reason=" << int(reason) << std::endl;
            s->ws_post([s, reason]() { s->raw_close(reason); });
        }
    }

private:
    void finish_join(const std::shared_ptr<Session>& s,
        const std::optional<ChatService::TokenIdentity>& id)
    {
        if (!id) { s->raw_close(KICK_AUTH); return; }

        const PlayerId pid = next_id_++;
        s->game_id = pid;
        s->arm_timer(std::chrono::seconds(90));     // авторизован: обычный дедлайн простоя

        std::weak_ptr<Session> w = s;
        boost::asio::post(game_io_, [this, pid, w, uid = id->user_id, name = id->username]()
            {
                sessions_[pid] = w;

                // 1. Создаём UDP-сессию игрока.
                auto info = udp_->create_session(pid);

                // 2. Отправляем обычный Welcome по TCP.
                game_->on_join(pid, uid, name);

                // 3. Отправляем параметры UDP отдельным TCP-пакетом.
                proto::Writer packet;
                packet.u8(proto::S2C_UDP_INFO);
                packet.u16(info.port);
                packet.u32(info.sid);
                packet.bytes(info.key.data(), info.key.size());

                send(pid, packet.b, true);
            });
    }
    
    boost::asio::io_context& game_io_;
    boost::asio::steady_timer stat_timer_{ game_io_ };
    ChatService& auth_;
    IGameHandler* game_ = nullptr;
    std::unique_ptr<UdpTransport> udp_;
    std::atomic<PlayerId> next_id_{ 1 };
    std::unordered_map<PlayerId, std::weak_ptr<Session>> sessions_;   // только игровой поток
};