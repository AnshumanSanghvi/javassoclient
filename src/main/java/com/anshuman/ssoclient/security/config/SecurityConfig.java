package com.anshuman.ssoclient.security.config;

import com.anshuman.ssoclient.security.CustomAuthenticationProvider;
import com.anshuman.ssoclient.security.CustomUserDetailsService;
import com.anshuman.ssoclient.security.JwtConverter;
import com.anshuman.ssoclient.security.filter.JwtFilter;
import com.anshuman.ssoclient.security.intercepter.CustomAuthenticationFailureFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SuppressWarnings("deprecation")
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

    public static final String ADMIN = "admin";
    public static final String USER = "user";

    private final JwtConverter jwtConverter;

    private final CustomAuthenticationProvider customAuthenticationProvider;

    private final CustomUserDetailsService userDetailsService;

//    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
//
    private final JwtFilter jwtFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider);
        auth.userDetailsService(userDetailsService);
    }

    @Bean
    public ForwardedHeaderFilter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, "/api/hello").permitAll()
                .antMatchers(HttpMethod.GET, "/api/admin/**").hasRole(ADMIN)
                .antMatchers(HttpMethod.GET, "/api/user/**").hasRole(USER)
                .antMatchers(HttpMethod.GET, "/api/admin-and-user/**").hasAnyRole(ADMIN, USER).anyRequest().authenticated()
                .and().addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        http.oauth2ResourceServer()
                .jwt().jwtAuthenticationConverter(jwtConverter);
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureFilter();
    }
}
