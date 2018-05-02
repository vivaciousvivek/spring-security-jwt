package com.example.security.config.filter;

import com.example.security.util.security.JwtTokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

import static com.example.security.util.AppConstant.HEADER_STRING;
import static com.example.security.util.AppConstant.TOKEN_PREFIX;

/**
 * Authentication Filer should use appropriate filter(AbstractAuthenticationProcessingFilter,
 * OncePerRequestFilter ).
 *
 * <p>This filter class reads JWT authentication token from the Authorization header of all the
 * requests.
 *
 * <p>validates the token.
 *
 * <p>loads the user details associated with that token.
 *
 * <p>Sets the user details in Spring Security’s SecurityContext. Spring Security uses the user
 * details to perform authorization checks.
 *
 * <p>We can also access the user details stored in the SecurityContext in our controllers to
 * perform our business logic.
 *
 * @author VIVEK KUMAR SINGH
 * @since (2018-04-30 12:49:08)
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  @Autowired private JwtTokenProvider jwtTokenProvider;
  @Autowired private UserDetailsService userDetailsService;

  /**
   * Logic to authenticate user and token
   *
   * @param request
   * @param response
   * @param filterChain
   * @throws ServletException
   * @throws IOException
   */
  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String jwt = getJwtFromRequest(request);
    String username = null;
    if (StringUtils.hasText(jwt)) {
      try {
        username = jwtTokenProvider.getUsernameFromToken(jwt);
      } catch (IllegalArgumentException e) {
        logger.error("an error occurred during getting username from token", e);
      } catch (ExpiredJwtException e) {
        logger.warn("the token is expired and not valid anymore", e);
      } catch (SignatureException e) {
        logger.error("Authentication Failed. Username or Password not valid.");
      }
    } else {
      logger.warn("couldn't find bearer string, will ignore the header");
    }

    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = userDetailsService.loadUserByUsername(username);
      if (jwtTokenProvider.validateToken(jwt, userDetails)) {
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        logger.info("authenticated user " + username + ", setting security context");

        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    }

    filterChain.doFilter(request, response);
  }

  private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader(HEADER_STRING);
    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
      return bearerToken.substring(7, bearerToken.length());
    }
    return null;
  }
}

/*
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
  @Autowired private JwtTokenProvider jwtTokenProvider;
  @Autowired private UserDetailsService userDetailsService;

  public JwtAuthenticationFilter() {
    */
/** This filter is going to hit for every URL so here is "**" *//*

                                                                  super("/**");
                                                                }

                                                                */
/**
 * Logic to authenticate user and token
 *
 * @param request
 * @param response
 * @return
 * @throws AuthenticationException
 * @throws IOException
 * @throws ServletException
 *//*

     @Override
     public Authentication attemptAuthentication(
         HttpServletRequest request, HttpServletResponse response)
         throws AuthenticationException, IOException, ServletException {
       String jwt = getJwtFromRequest(request);
       String username = null;
       if (StringUtils.hasText(jwt)) {
         try {
           username = jwtTokenProvider.getUsernameFromToken(jwt);
         } catch (IllegalArgumentException e) {
           logger.error("an error occured during getting username from token", e);
         } catch (ExpiredJwtException e) {
           logger.warn("the token is expired and not valid anymore", e);
         } catch (SignatureException e) {
           logger.error("Authentication Failed. Username or Password not valid.");
         }
       } else {
         logger.warn("couldn't find bearer string, will ignore the header");
       }

       UsernamePasswordAuthenticationToken authentication = null;
       if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
         UserDetails userDetails = userDetailsService.loadUserByUsername(username);
         if (jwtTokenProvider.validateToken(jwt, userDetails)) {
           authentication =
               new UsernamePasswordAuthenticationToken(
                   userDetails,
                   null,
                   Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));
           authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

           logger.info("authenticated user " + username + ", setting security context");

           SecurityContextHolder.getContext().setAuthentication(authentication);
         }
       }

       return getAuthenticationManager().authenticate(authentication);
     }

     private String getJwtFromRequest(HttpServletRequest request) {
       String bearerToken = request.getHeader(HEADER_STRING);
       if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
         return bearerToken.substring(7, bearerToken.length());
       }
       return null;
     }
   }
   */
