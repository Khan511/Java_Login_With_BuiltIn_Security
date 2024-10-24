package com.userSecurity.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.annotation.Bean;
// import com.userSecurity.security.entity.RoleEntity;
// import com.userSecurity.security.domain.RequestContext;
// import com.userSecurity.security.enumeration.Authority;
import com.userSecurity.security.repository.RoleRepository;

// import io.github.cdimascio.dotenv.Dotenv;

import org.springframework.boot.autoconfigure.SpringBootApplication;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {

		SpringApplication.run(Application.class, args);

	}

	@Bean
	CommandLineRunner commandLineRunner(RoleRepository repository) {
		return args -> {

			// // Bcrypting the existing password
			// BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
			// String rawPassword = "12345";
			// String encodedPassword = encoder.encode(rawPassword);
			// System.out.println("The encoded password id: " + encodedPassword);

			// RequestContext.setUserId(0L);
			// var userRole = new RoleEntity();
			// userRole.setName(Authority.USER.name());
			// userRole.setAuthority(Authority.USER);
			// repository.save(userRole);

			// var adminRole = new RoleEntity();
			// adminRole.setName(Authority.ADMIN.name());
			// adminRole.setAuthority(Authority.ADMIN);
			// repository.save(adminRole);

			// RequestContext.start();
		};
	}
}
