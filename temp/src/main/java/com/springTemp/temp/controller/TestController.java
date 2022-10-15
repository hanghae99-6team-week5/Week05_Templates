package com.springTemp.temp.controller;

import com.springTemp.temp.exception.PrivateException;
import com.springTemp.temp.exception.PrivateResponseBody;
import com.springTemp.temp.exception.StatusCode;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Arrays;

@Controller
@RequiredArgsConstructor
public class TestController {

    private final Environment env;

    @GetMapping("/api/test/getERR")
    public void getPosts(){
        throw new PrivateException(StatusCode.INTERNAL_SERVER_ERROR_PLZ_CHECK);
    }

    @GetMapping("/api/test/ok")
    public ResponseEntity<PrivateResponseBody> getPosts_ok(){
        return new ResponseEntity<>(new PrivateResponseBody(StatusCode.OK , null), HttpStatus.OK);
    }

    @GetMapping("/api/logintest")
    public ResponseEntity<PrivateResponseBody> getLoginTest(){
        return new ResponseEntity<>(new PrivateResponseBody(StatusCode.OK,"로그인 테스트 성공"), HttpStatus.OK);
    }

    //profile 조회
    @GetMapping(value="/api/test/profile")
    public String getProfile(){
        return Arrays.stream(env.getActiveProfiles())
                .findFirst()
                .orElse("");
    }
}
