#pragma once
#include <string>
#include <librdkafka/rdkafka.h>

class KafkaProducer {
public:
    KafkaProducer(const std::string& brokers, const std::string& topic);
    ~KafkaProducer();
    bool send(const std::string& key, const std::string& payload);

private:
    rd_kafka_t* rk_;
    rd_kafka_topic_t* rkt_;
};
