package com.ecommerce.project.controller;

import com.ecommerce.project.jwt.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

@RestController
/*@CrossOrigin(origins = "http://localhost:8080", exposedHeaders = "token")*/
public class SecurityController {
    private static final Logger logger = LoggerFactory.getLogger(SecurityController.class);

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;


    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }


    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userEndPoint() {
        return "hello user!!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndPoint() {
        return "hello admin!!";
    }

    @PostMapping("/signing")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest request1){

        logger.info("authentication 55 {}",request1.getPassword(),request1.getUsername());
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request1.getUsername(), request1.getPassword()
                    ));
            logger.info("authentication 64 {}",authentication.getPrincipal());
        }
        catch (AuthenticationException e) {
            Map<String, Object> errors = new HashMap<>();
            errors.put("message", "Bad credentials");
            errors.put("status", false);
            //errors.put("timestamp", String.valueOf(System.currentTimeMillis()));
            return new ResponseEntity<>(errors, HttpStatus.NOT_FOUND);


        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails=(UserDetails)authentication.getPrincipal();

        String jwtToken=jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles=userDetails.getAuthorities()
                .stream().map(GrantedAuthority::getAuthority)
                .toList();
        LoginResponse response=new LoginResponse(userDetails.getUsername(),roles,jwtToken);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
