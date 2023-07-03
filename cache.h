#include <iostream>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <condition_variable>
#include <sw/redis++/redis++.h>
using namespace sw::redis;

class ThreadSafeCache {
public:
    ThreadSafeCache(Redis* redis) : redis(redis), workloadThreshold(8192), isClearingCache(false) {}

    void addToCache(std::string key, std::string value) {
        std::unique_lock<std::mutex> lock(cacheMutex);
        if (cache.size() >= workloadThreshold) {
            if (!isClearingCache) {
                int to_sync = workloadThreshold / 8;
                cache[key] = value;
                isClearingCache = true;
                std::vector<std::string> keys;
                int count = 0; 
                keys.reserve(to_sync);
                for (const auto& pair : cache) {
                    keys.push_back(pair.first);
                    count++;
                    if (count > to_sync) break;
                }
                std::thread backgroundTask(&ThreadSafeCache::performWorkload, this, keys);
                backgroundTask.detach();
            }
            else {
                //redis.set("wait",std::to_string(cache.size()));
                cacheCondition.wait(lock, [this]() {
                    return cache.size() <= workloadThreshold;
                });
                cache[key] = value;
            }
        } else {
            cache[key] = value;
        }
    }

    std::string getFromCache(std::string key) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(key);
        if (it == cache.end()) {
            return "";
        }
        return cache[key];
    }

    void emptyCache() { 
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto pipeline = redis->pipeline();
        for (const auto& pair : cache) { 
            pipeline.set(pair.first,pair.second);
        }
        pipeline.exec();
        cache.clear();        
    }

private:
    void performWorkload(const std::vector<std::string>& keys) {
        //redis.set("perform","workload");
        auto pipeline = redis->pipeline();
        for (const auto& key : keys) { 
            auto value = cache[key];
            pipeline.set(key,value);
        }
        pipeline.exec();
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            // Clear the existing elements from the cache
            for (const auto& key : keys) {
                cache.erase(key);
            }
            isClearingCache = false;
        }
        cacheCondition.notify_all();
    }

    std::unordered_map<std::string, std::string> cache;
    std::mutex cacheMutex;
    Redis* redis;
    std::condition_variable cacheCondition;
    const size_t workloadThreshold;
    std::atomic<bool> isClearingCache;
};