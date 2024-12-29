package com.anshuman.ssoclient.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@AllArgsConstructor
public class ApiErrorResponse {
    private int _resultflag;
    private String message;
    private Object data;
}