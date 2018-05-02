package com.example.security.config.security;

import com.example.security.config.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuration about which resource to be protected and which not can be configured.
 *
 * <p>We will use JWT custom filters instead of LDAP filters(provided default by Spring)
 *
 * @author VIVEK KUMAR SINGH
 * @since (2018-04-30 12:44:32)
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) /*for method level security*/
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
  @Autowired private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

  @Autowired private UserDetailsService userDetailsService;

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtAuthenticationFilter authenticationFilter() {
    return new JwtAuthenticationFilter();
  }

  /** Configured AuthenticationManager to authenticate a user in the login API. */
  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    /**
     * If u want specific request to be not authorized, then use permitAll(), else use antMatchers()
     * and then authenticated(){will ask spring security for from where these url should
     * authenticated, then spring will send this to userdetailservice}.
     *
     * <p>If user is not authenticated then we will move it to the exceptionHandling() and add some
     * entry point(for redirecting the error messages)
     *
     * <p>After that we need to maintain a session using stateless session creation policy
     */
    http.cors().and().csrf().disable();
    http.authorizeRequests()
        .antMatchers("/api/auth/**")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .exceptionHandling()
        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    /** Now we need to add the filters which we created */
    http.addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    /** We can also use cache control headers */
    http.headers().cacheControl();
  }

  /**
   * AuthenticationManagerBuilder is used to create an AuthenticationManager instance which is the
   * main Spring Security interface for authenticating a user.
   *
   * <p>You can use AuthenticationManagerBuilder to build in-memory authentication, LDAP
   * authentication, JDBC authentication, or add your custom authentication provider.
   *
   * <p>In our example, we’ve provided our CustomUserDetailsService and a passwordEncoder to build
   * the AuthenticationManager.
   *
   * @param auth
   * @throws Exception
   */
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
  }
}
