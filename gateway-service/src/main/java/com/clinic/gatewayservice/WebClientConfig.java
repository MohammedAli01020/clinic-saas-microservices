package com.clinic.gatewayservice;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

@Configuration
public class WebClientConfig {

    @Bean
    @LoadBalanced
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(HttpClient.create()
                        .tcpConfiguration(tcp -> tcp.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                                .doOnConnected(conn -> conn.addHandlerLast(new ReadTimeoutHandler(5))
                                        .addHandlerLast(new WriteTimeoutHandler(5))))));
    }
}
