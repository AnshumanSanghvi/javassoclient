package com.anshuman.ssoclient.security.filter;

import com.anshuman.ssoclient.exception.ApiErrorResponse;
import com.anshuman.ssoclient.security.CustomUserDetailsService;
import com.anshuman.ssoclient.security.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        String accessToken = Optional
                .ofNullable(httpServletRequest.getHeader("Authorization"))
                .filter(header -> header.startsWith("Bearer "))
                .map(header -> header.replace("Bearer ", ""))
                .map(String::trim)
                .orElse(null);

        String rawCookie = httpServletRequest.getHeader("Cookie");
        String springAdmin ="";

        if(null !=httpServletRequest.getHeader("X-CUSTOM"))
            springAdmin=httpServletRequest.getHeader("X-CUSTOM");

        boolean isFrom =false;
        boolean isexpired =false;
        boolean webApiClient = false;

        if(rawCookie != null) {
            String[] rawCookieParams = rawCookie.split(";");

            for (String rawCookieNameAndValue : rawCookieParams) {
                log.debug("found raw cookie param: {}", rawCookieNameAndValue);

                // extract the access token from the cookie
                if (null == accessToken && rawCookieNameAndValue.contains("accessToken=")) {
                    accessToken = rawCookieNameAndValue.split("=")[1];
                }

                // determine whether the source of the API call is from the web or from the webApiClient
                // and set its respective flag to true
                if (rawCookieNameAndValue.contains("from=")) {

                    String[] rawCookieNameAndValuePair = rawCookieNameAndValue.split("=");
                    if (null != rawCookieNameAndValuePair[1]) {
                        if (rawCookieNameAndValuePair[1].equals("web"))
                            isFrom = true;
                        else if (rawCookieNameAndValuePair[1].equals("webApiClient"))
                            webApiClient = true;
                    }
                }

            }
        }

        String token = null;
        Jwt jwt = null;
        String userName = null;
        String ErrorMessage = "NO";

        if (!httpServletRequest.getRequestURL().toString().contains("login")
                && !httpServletRequest.getRequestURL().toString().contains("/js/")
                && !httpServletRequest.getRequestURL().toString().contains("/images/")
                && !httpServletRequest.getRequestURL().toString().contains("favicon.ico")
                && !httpServletRequest.getRequestURL().toString().contains("/css/")
                && !httpServletRequest.getRequestURL().toString().endsWith("/authenticateapi")
                && !httpServletRequest.getRequestURL().toString().endsWith("/captchaImage")
                && !httpServletRequest.getRequestURL().toString().endsWith("/forgotPassword")
                && !httpServletRequest.getRequestURL().toString().endsWith("/resetPassword")
                && !httpServletRequest.getRequestURL().toString().endsWith("/vendor/create")
                && !httpServletRequest.getRequestURL().toString().endsWith("/vendor/save")
                && !httpServletRequest.getRequestURL().toString().endsWith("/")
                && !springAdmin.equals("springAdminapicall")
                && !webApiClient
        ) {
            if (null != accessToken) {
                jwt = jwtUtil.convertToJwt(accessToken);
                if (null != jwt) {
                    try {
                        userName = jwtUtil.extractUsername(jwt);
                    }
                    catch (Exception e) {
                        log.error(e.getMessage());
                        log.warn("JWT Token Not Valid!!!!--> "+httpServletRequest.getRequestURL()+" accessToken-->"+accessToken);
                        ErrorMessage = "JWT Token Not Valid!!!!--> "+httpServletRequest.getRequestURL();
                    }    
                }
            } else {
                isexpired = true;
                log.warn("JWT Authentication failed as the authorization header was null");
                ErrorMessage = "JWT Authentication failed as the authorization header was null";
            }
        }


        if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            log.debug("checking authentication for user: {}", userName);
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
            if (userDetails != null) {
                if (!jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    log.debug("authenticated user: {}", userName);

//                    Cookie jsessionidCookie = new Cookie("accessToken", accessToken);
//                    jsessionidCookie.setPath("/");
//                    jsessionidCookie.setMaxAge(0);  // Set to expire immediately
//                    jsessionidCookie.setHttpOnly(true);  // Ensure this is consistent with how it was set
//                    httpServletResponse.addCookie(jsessionidCookie);
                    httpServletRequest.setAttribute("accessToken", accessToken);
                }else {
                    log.warn("JWT Token either expired or blacklisted");
                    ErrorMessage = "Could not authenticate user from the JWT token";
                }
            }else {
                log.warn("Could not authenticate user from the JWT token");
                ErrorMessage = "Could not authenticate user from the JWT token";
            }
        }
        boolean fnl = true;
        if (isexpired || isFrom)
            fnl=false;
        //System.out.println("isexpired= "+isexpired+"---isform= "+isform+"---fnl= "+fnl);
        if ((ErrorMessage == null || !ErrorMessage.equals("NO")) && fnl) {
            System.out.println(httpServletRequest.getRequestURL().toString()+" accessToken "+accessToken);
            ObjectMapper mapper = new ObjectMapper();
            String jsonString = mapper.writeValueAsString(new ApiErrorResponse(2, ErrorMessage, ""));
            httpServletResponse.setContentLength(jsonString.length());
            httpServletResponse.getWriter().write(jsonString.toString());
        } else {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }
    }
}