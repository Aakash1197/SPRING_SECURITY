package com.ecommerce.project.controller;

import com.ecommerce.project.jwt.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.ecommerce.project.jwt.AuthTokenFilter;
import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class securityConfig {
// Writing your own Security Filter with Spring Security

    @Autowired
    private AuthEntryPointJwt  unauthorizedHandler;

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Autowired
    DataSource dataSource;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        ////normal authentication with default mechanism
        // http.authorizeHttpRequests((request)-> request.anyRequest().authenticated());
       // JWT authentication
        http.csrf(AbstractHttpConfigurer::disable);

       http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user",
                                "/admin", "/hello","/signing").
                        permitAll()
               .requestMatchers("/hello").hasAuthority("ROLE_USER")
                .requestMatchers("/hello").hasAuthority("ROLE_ADMIN")
               .requestMatchers("/user").hasAuthority("ROLE_USER")
               .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
               .requestMatchers("/signing").hasAuthority("ROLE_USER")
               .requestMatchers("/signing").hasAuthority("ROLE_ADMIN")
       );

      /*  http.authorizeHttpRequests( authorizeRequest ->
                authorizeRequest.requestMatchers("/signing").permitAll()
                        .anyRequest().authenticated());*/

    /*    http.authorizeHttpRequests( authorizeRequest ->
                authorizeRequest.requestMatchers("/signing")
                .hasAuthority("{ROLE_USER,ROLE_ADMIN}")
                        .anyRequest().authenticated());*/





    //form based authentication
    //http.formLogin(withDefaults());

    //basic authentication
   /* Statelessness. In REST architecture, statelessness refers to a
       communication method in which the server completes every client
        request independently of all previous requests. */
        //what if we want to maintain statelless?
        // Means we need to disable the Jsession ID
    http.sessionManagement((session)-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    http.exceptionHandling(exception ->
        exception.authenticationEntryPoint(unauthorizedHandler)

            );



    //normal authentication with default mechanism
   // http.httpBasic(withDefaults());

        http.headers(headers ->
              headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
        );


        //our own filter execution by defualt addFilterBefore() methode got executed first
        http.addFilterBefore(authTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);
    return http.build();

    }

    //In-memory authentication
   /* @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1= User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails admin= User.withUsername("admin")
                .password(passwordEncoder().encode("adminpass"))
                .roles("ADMIN")
                .build();
      // return new InMemoryUserDetailsManager(user1, admin);
        JdbcUserDetailsManager userDetailsManager =
                new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;



    }*/

    @Bean
    public UserDetailsService userDetailsService(DataSource  dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
    return args -> {
        JdbcUserDetailsManager manager =
                (JdbcUserDetailsManager) userDetailsService;
        UserDetails user1= User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        UserDetails admin= User.withUsername("admin")
                .password(passwordEncoder().encode("adminpass"))
                .roles("ADMIN")
                .build();
        JdbcUserDetailsManager userDetailsManager =
                new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
    };
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
/*    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService(dataSource));
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }



}
