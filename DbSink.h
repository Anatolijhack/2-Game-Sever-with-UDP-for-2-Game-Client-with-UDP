// DbSink.h
#pragma once
#include "ResultSink.h"
#include "MatchRepo.h"
#include "ThreadPool.h"     // ваш заголовок пула
#include "Outbox.h"

class DbSink : public IResultSink
{
public:
    DbSink(ThreadPool& workers, MatchRepository& repo, Outbox& box)
        : workers_(workers), repo_(repo), box_(box) {}

    void save(MatchResultRecord r) override
    {
        MatchResultRecord copy = r;     // для запасного пути
        const bool queued = workers_.try_push_task(
            [this, rec = std::move(r)]()
            {
                if (!repo_.save(rec))
                {
                    std::cerr << "[db] failed, to outbox: " << rec.match_guid << std::endl;
                    box_.append(rec);
                }
            }, 0);

        if (!queued)
        {
            std::cerr << "[db] queue full, to outbox: " << copy.match_guid << std::endl;
            box_.append(copy);
        }
    }

    // Вызывать раз в 30 с (см. ниже)
    void retry_outbox()
    {
        box_.flush([this](const MatchResultRecord& r) { return repo_.save(r); });
    }

private:
    ThreadPool& workers_;
    MatchRepository& repo_;
    Outbox& box_;
};