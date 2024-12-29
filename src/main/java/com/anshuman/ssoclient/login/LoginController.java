package com.anshuman.ssoclient.login;


import com.anshuman.ssoclient.security.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;


@Controller
@RequestMapping(value = "")
@Slf4j
public class LoginController {

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private ServletRequest httpServletRequest;

    @GetMapping({"/signin", "/login"})
    public String signin(HttpServletRequest request, HttpServletResponse response, Model model,
                         final RedirectAttributes redirectAttributes) {
        try {
            log.info("LoginController.login/signin " + request.getRequestURL() + " " + request.getContextPath());

            try {

                String accessToken = Optional.ofNullable(request.getAttribute("accessToken"))
                        .map(String::valueOf)
                        .orElse(null);
                Jwt jwt = Optional.ofNullable(accessToken)
                        .map(jwtUtil::convertToJwt)
                        .orElse(null);

                if (null != accessToken && null != jwt) {
                    try {
                        boolean isTokenExpired = jwtUtil.isTokenExpired(jwt);
                        if (isTokenExpired)
                            log.warn("JWT token expired: {}", jwt.getClaims().get("exp"));

                        boolean isTokenBlacklisted = jwtUtil.isTokenBlacklisted(jwt);
                        if (isTokenBlacklisted)
                            log.warn("JWT Token black-listed: {}", jwt.getClaims().get("jti"));

                        if (isTokenExpired || isTokenBlacklisted)
                            return "redirect:/logout";

                        Cookie jsessionidCookie = new Cookie("accessToken", accessToken);
                        jsessionidCookie.setPath("/");
                        jsessionidCookie.setMaxAge(0);  // Set to expire immediately
                        jsessionidCookie.setHttpOnly(true);  // Ensure this is consistent with how it was set
                        response.addCookie(jsessionidCookie);
                    } catch (JwtException e) {
                        log.error("error in preparing JWT from token code, {}", e.getMessage());
                        throw new RuntimeException(e);
                    }
                } else
                    log.warn("No accessToken found in cookies");

                Optional.ofNullable(request.getCookies())
                        .stream()
                        .flatMap(Arrays::stream)
                        .forEach(cookie -> {
                                cookie.setMaxAge(0);
                                cookie.setPath("/");
                                response.addCookie(cookie);
                        });
            } catch (Exception e) {
                log.error("error in extracting and validating token during sign-in, {}", e.getMessage());
            }

            HttpSession session = request.getSession(false);

            if (session != null) {

                Map<String, ?> inputFlashMap = RequestContextUtils.getInputFlashMap(request);
                if (inputFlashMap != null) {
                    Optional.ofNullable(inputFlashMap.get("successMessage"))
                            .map(String::valueOf)
                            .ifPresentOrElse(message -> model.addAttribute("success", message),
                                    () -> log.debug("successMessage not found"));

                    Optional.ofNullable(inputFlashMap.get("failureMessage"))
                            .map(String::valueOf)
                            .ifPresentOrElse(message -> model.addAttribute("failureMessage", message),
                                    () -> log.debug("failureMessage not found"));

                    Optional.ofNullable(inputFlashMap.get("pervious_page"))
                            .map(String::valueOf)
                            .ifPresentOrElse(message -> {
                                redirectAttributes.addFlashAttribute("pervious_page", message);
                                model.addAttribute("pervious_page", message);
                            }, () -> log.debug("previous_page not found"));
                }

                String randomKey = UUID.randomUUID().toString();
                request.getSession().setAttribute("key", randomKey);
                request.getSession().removeAttribute("custom_message");
                request.getSession().removeAttribute("error_controller_message");
            }
            else log.warn("Session was null");


        } catch (Exception e) {
            log.error("Error in login/signin, {}", e.getMessage(), e);
        }
        return "hrms/login";
    }

    @GetMapping({"/logoutsignoutt", "/"})
    public String logout(HttpSession session, HttpServletRequest request, HttpServletResponse response, final RedirectAttributes redirectAttributes) {
        System.out.println("LoginController.logout()");
        try {
            session.invalidate();
            Arrays.stream(request.getCookies()).forEach(cookie -> {
                cookie.setMaxAge(0);
                cookie.setPath("/");
                response.addCookie(cookie);
            });
            redirectAttributes.addFlashAttribute("successMessage", "User Is Logout Successfully...!!!");
        } catch (Exception e) {
            log.error("Error in logout/signout: {}", e.getMessage(), e);
        }

        return "redirect:/logout";
    }

    public void setLoginFailuare(String userId, HttpServletRequest request) {
        //login failure code
    }

}
