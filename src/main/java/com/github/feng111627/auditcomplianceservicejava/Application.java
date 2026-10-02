package com.github.feng111627.auditcomplianceservicejava;

import com.github.feng111627.auditcomplianceservicejava.alert.AlertForwarder;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class Application implements CommandLineRunner {

    private final AlertForwarder forwarder;

    public Application(AlertForwarder forwarder) {
        this.forwarder = forwarder;
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Override
    public void run(String... args) {
        forwarder.start();
    }
}
