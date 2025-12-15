package com.clinic.authservice.config;


import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaTopicConfig {

    @Bean
    public NewTopic tenantCreatedTopic() {
        return TopicBuilder.name("tenant-created").partitions(2).replicas(2).build();
    }

    @Bean
    public NewTopic emailVerificationTopic() {
        return TopicBuilder.name("email-verification").partitions(2).replicas(2).build();
    }

    @Bean
    public NewTopic tenantCreatedDlq() {
        return TopicBuilder.name("tenant-created-dlq").partitions(1).replicas(2).build();
    }
}
