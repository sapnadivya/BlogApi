package com.restapi.blog.service;

import com.restapi.blog.payload.LoginDto;
import com.restapi.blog.payload.RegisterDto;

public interface AuthService {

    String login(LoginDto loginDto);
    String register(RegisterDto registerDto);

}
