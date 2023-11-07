package com.restapi.blog.service.impl;

import com.restapi.blog.entity.Role;
import com.restapi.blog.entity.User;
import com.restapi.blog.exception.BlogApiException;
import com.restapi.blog.payload.LoginDto;
import com.restapi.blog.payload.RegisterDto;
import com.restapi.blog.repository.RoleRepository;
import com.restapi.blog.repository.UserRepository;
import com.restapi.blog.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;


@Service
public class AuthServiceImpl implements AuthService {
    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository=userRepository;
        this.roleRepository=roleRepository;
        this.passwordEncoder=passwordEncoder;
    }
//login method
    @Override
    public String login(LoginDto loginDto) {
        Authentication authentication = authenticationManager.
                authenticate(new UsernamePasswordAuthenticationToken(
                        loginDto.getUsernameOrEmail(), loginDto.getPassword()));
//store authentication object to spring security context holder
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return "User login successfully";
    }

    //register method
    @Override
    public String register(RegisterDto registerDto) {
        //1. we will check whether user name is exists in database or not
        if(userRepository.existsByUsername(registerDto.getUsername())){
            throw  new BlogApiException(HttpStatus.BAD_REQUEST,"username already exists");
        }
        //2.we have to check user email exists in database or not.
        if(userRepository.existsByEmail(registerDto.getEmail())){
            throw  new BlogApiException(HttpStatus.BAD_REQUEST,"this email already registered with us try wih some other email id");

        }
        User user=new User();
        user.setName(registerDto.getName());
        user.setEmail(registerDto.getEmail());
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));

        Set<Role> roles=new HashSet<>();
        Role userRole=roleRepository.findByName("ROLE_USER").get();
        roles.add(userRole);
        user.setRoles(roles);
        userRepository.save(user);
        return "user registered succesfully !!!";
    }


}
