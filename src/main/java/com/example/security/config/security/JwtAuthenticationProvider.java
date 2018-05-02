//package com.example.security.config.security;
//
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//
///**
// * This class provide major processing like authentication
// *
// * @author VIVEK KUMAR SINGH
// * @since (2018-04-30 19:18:24)
// */
//public class JwtAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
//  @Override
//  protected void additionalAuthenticationChecks(
//      UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
//      throws AuthenticationException {}
//
//  @Override
//  protected UserDetails retrieveUser(
//      String username, UsernamePasswordAuthenticationToken authentication)
//      throws AuthenticationException {
//    return null;
//  }
//
//  @Override
//  public boolean supports(Class<?> authentication) {
//    return false;
//  }
//}
