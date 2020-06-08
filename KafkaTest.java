package com.example.messagingstompwebsocket;

import org.apache.kafka.streams.StreamsBuilder;


/**
 * for test kafka stream
 */

public class KafkaTest {

    public static void main(String[] args) throws InterruptedException {
        StreamsBuilder builder = KafkaUtil.config();
        builder.<String, String>stream("test")   //filter 过滤 保留record value为Hello开头的结果
                .filter((k, v) -> v.contains("pingan")).foreach((k, v) -> System.out.println(v));
        //.filter(log -> {  }).map (log -> ws.send(log));
        //.flatMapValues(value -> value))

        KafkaUtil.start(builder);

    }
}
