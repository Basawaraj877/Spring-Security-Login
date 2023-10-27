package com.jwt.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SpringJwtAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtAppApplication.class, args);
	}

}
