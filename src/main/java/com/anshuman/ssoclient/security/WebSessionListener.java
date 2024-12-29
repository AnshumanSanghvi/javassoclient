package com.anshuman.ssoclient.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

@WebListener
public class WebSessionListener implements HttpSessionListener {

	private static final Logger logger = LoggerFactory.getLogger(WebSessionListener.class);

	@Override
	public void sessionCreated(HttpSessionEvent se) {
		HttpSessionListener.super.sessionCreated(se);
		logger.info("session created:- " + se.getSession().getId());
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent se) {
		HttpSessionListener.super.sessionDestroyed(se);
		logger.info("userID is:- " + se.getSession().getAttribute("userId"));
		logger.info("sessionDestroyed is, " + se.getSession().getId());
	}
}