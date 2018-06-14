package com.spring.security.JWTSecure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring.security.JWTSecure.filter.JWTAuthenticationFilter;
import com.spring.security.JWTSecure.filter.JWTLoginFilter;

//configure users , their roles and  other custom filters

@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()
				// No need authentication.
				.antMatchers("/").permitAll() //
				.antMatchers(HttpMethod.POST, "/login").permitAll() //
				.antMatchers(HttpMethod.GET, "/login").permitAll() // For Test on Browser
				//.antMatchers("/test").access("hasRole('ADMIN')")
				// Need authentication.
				.anyRequest().authenticated()
				//
				.and()
				// Add Filter 1 - JWTLoginFilter
				.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),UsernamePasswordAuthenticationFilter.class)
				// Add Filter 2 - JWTAuthenticationFilter
				.addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		String tomPassword = "12345678";
		String jerryPassword = "12345678";
		String dbaPassword = "12345678";
		String guestPassword = "12345678";
		
		InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> 	mngConfig = auth.inMemoryAuthentication();

		UserDetails user1 = User.withUsername("tom").password(this.passwordEncoder().encode(tomPassword)).roles("USER").build();
		UserDetails admin1 = User.withUsername("jerry").password(this.passwordEncoder().encode(jerryPassword)).roles("ADMIN").build();
		UserDetails dba1 = User.withUsername("dba").password(this.passwordEncoder().encode(dbaPassword)).roles("USER").build();
		UserDetails guest1 = User.withUsername("guest").password(this.passwordEncoder().encode(guestPassword)).roles("USER").build();

		mngConfig.withUser(user1);
		mngConfig.withUser(admin1);
		mngConfig.withUser(dba1);
		mngConfig.withUser(guest1);

	}

}