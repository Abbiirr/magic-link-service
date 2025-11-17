package org.example.magiclink;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class MagicLinkApplication {

    public static void main(String[] args) {
        SpringApplication.run(MagicLinkApplication.class, args);
    }

}
