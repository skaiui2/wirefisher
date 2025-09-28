#include "kafka_producer.h"
#include <iostream>

KafkaProducer::KafkaProducer(const std::string& brokers, const std::string& topic) {
    char errstr[512];

    rd_kafka_conf_t* conf = rd_kafka_conf_new();

    if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers.c_str(),
                          errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        throw std::runtime_error(std::string("Failed to set bootstrap.servers: ") + errstr);
    }

    rk_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk_) {
        throw std::runtime_error(std::string("Failed to create producer: ") + errstr);
    }

    rkt_ = rd_kafka_topic_new(rk_, topic.c_str(), nullptr);
    if (!rkt_) {
        throw std::runtime_error("Failed to create topic object");
    }
}


KafkaProducer::~KafkaProducer() {
    rd_kafka_flush(rk_, 5000);
    rd_kafka_topic_destroy(rkt_);
    rd_kafka_destroy(rk_);
}

bool KafkaProducer::send(const std::string& key, const std::string& payload) {
    if (rd_kafka_produce(
            rkt_, RD_KAFKA_PARTITION_UA,
            RD_KAFKA_MSG_F_COPY,
            (void*)payload.c_str(), payload.size(),
            key.empty() ? nullptr : key.c_str(),
            key.empty() ? 0 : key.size(),
            nullptr) == -1) {
        std::cerr << "Produce failed: " << rd_kafka_err2str(rd_kafka_last_error()) << std::endl;
        return false;
    }
    rd_kafka_poll(rk_, 0);
    return true;
}
