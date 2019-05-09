package com.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//add our users for in memory authentication
		
		UserBuilder users = User.withDefaultPasswordEncoder();
		
		auth.inMemoryAuthentication()
			.withUser(users.username("john").password("test1234").roles("EMPLOYEE"))
			.withUser(users.username("mary").password("test1234").roles("EMPLOYEE", "MANAGER"))
			.withUser(users.username("susan").password("test1234").roles("EMPLOYEE", "ADMIN"));
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()
				//.anyRequest().authenticated()
			.antMatchers("/").hasRole("EMPLOYEE")// it means anyone who has a role of employee can access the page with mapping "/"
			.antMatchers("/leaders/**").hasRole("MANAGER") // it means anyone who has a role of manager can access the page with mapping /leaders and its submappings.
			.antMatchers("/systems/**").hasRole("ADMIN")	// it means anyone who has a role of admin can access the page with mapping /systems and its submappings.
			.and()
			.formLogin()
				.loginPage("/showMyLoginPage")
				.loginProcessingUrl("/authenticateTheUser")
				.permitAll()
			.and()
			.logout().permitAll()
			.and()
			.exceptionHandling().accessDeniedPage("/access-denied");
		
	}
}
