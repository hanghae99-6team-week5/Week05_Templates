package com.springTemp.temp.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/*
    RestController에서 발생하는 모든 예외를 핸들링하기 위해 선언 -> @ControllerAdvice와 @ResponseBody를 합쳐놓은 어노테이션이다.
    @RestControllerAdvice가 선언된 클래스 내부의 메서드에 아래와 같이 어노테이션을 선언하고 처리할 예외 타입을 선언
    그러면 예외를 handleApiRequestException() 메서드에 정의된 로직으로 처리할 수 있게 된다 , 적용 범위를 설정해주지 않으면 전역으로 처리한다.
*/

@RestControllerAdvice
public class RestApiExceptionHandler {
    /*
    @ExceptionHandler 어노테이션을 메서드에 선언하고 특정 예외 클래스를 지정해주면 해당 예외가 발생했을 때 메서드에 정의한 로직으로 처리할 수 있다.
    @ControllerAdvice 또는 @RestControllerAdvice에 정의된 메서드가 아닌 일반 컨트롤러 단에 존재하는 메서드에 선언할 경우, 해당 Controller에만 적용된다.
    */

    @ExceptionHandler(value = { PrivateException.class })
    public ResponseEntity<Object> handleApiRequestException(PrivateException ex) {
        String errCode = ex.getStatusCode().getStatusCode();
        String errMSG = ex.getStatusCode().getStatusMsg();
        PrivateResponseBody privateResponseBody = new PrivateResponseBody();
        privateResponseBody.setStatusCode(errCode);
        privateResponseBody.setStatusMsg(errMSG);

        //백엔드측에서 log를 확인하여 어떤 에러가 발생하는지 표시함
        System.out.println("ERR Code : " + errCode + " ERR Msg : " + errMSG);

        return new ResponseEntity(privateResponseBody, ex.getStatusCode().getHttpStatus());
    }
}
