package com.ajie.web.exception;

import javax.servlet.ServletException;


public class AuthorizeException extends ServletException {

	private static final long serialVersionUID = 1L;

	public AuthorizeException() {

	}

	public AuthorizeException(Throwable e, String message) {
		super(message, e);
	}

	public AuthorizeException(String message) {
		super(message);
	}

	public AuthorizeException(Throwable e) {
		super(e);
	}
}
