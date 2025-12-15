package com.clinic.sharedlib.kafka;

import org.springframework.kafka.core.KafkaTemplate;

/**
 * Simple wrapper. Declare as @Service in each service that needs it (don't register here).
 * Keeps shared code minimal; services supply KafkaTemplate bean.
 */
public class KafkaProducerHelper {
    private final KafkaTemplate<String, Object> kafkaTemplate;

    public KafkaProducerHelper(KafkaTemplate<String, Object> kafkaTemplate){
        this.kafkaTemplate = kafkaTemplate;
    }

    public void send(String topic, String key, Object payload){
        kafkaTemplate.send(topic, key, payload);
    }

    public void send(String topic, Object payload){
        kafkaTemplate.send(topic, payload);
    }
}
