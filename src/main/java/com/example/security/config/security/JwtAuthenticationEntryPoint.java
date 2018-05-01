package com.example.security.config.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This class is used to return a 401 unauthorized error to clients that try to access a protected
 * resource without proper authentication.
 *
 * <p>It implements Spring Security’s AuthenticationEntryPoint interface.
 *
 * @author VIVEK KUMAR SINGH
 * @since (2018-04-30 12:59:09)
 */
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException, ServletException {
    logger.error("Responding with unauthorized error. Message - {}", authException.getMessage());
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
  }
}
