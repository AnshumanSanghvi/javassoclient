package com.anshuman.ssoclient.login;


import com.anshuman.ssoclient.login.model.JwtRequest;
import com.anshuman.ssoclient.security.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Optional;


@RestController
@RequestMapping("")
@Slf4j
public class WelcomeController {
	
	@Autowired
	private JwtUtil jwtTokenUtil;

	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	LoginController loginController;

	@GetMapping("/home")
	public String welcome() {
		return "Welcome to HRMS !!";
	}


	@RequestMapping(value = "/authenticateapi", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest, HttpServletRequest request,
													   HttpServletResponse response) throws Exception {
		String userId ="";
		try {

			final String token = Optional
					.ofNullable(request.getHeader("Authorization"))
					.filter(header -> header.startsWith("Bearer "))
					.map(header -> header.replace("Bearer ", ""))
					.map(String::trim)
					.orElseThrow(() -> new IllegalArgumentException("Invalid JWT token"));

			Jwt jwt = jwtTokenUtil.convertToJwt(token);
			String userName = jwtTokenUtil.extractUsername(jwt);
			final UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

			if (jwtTokenUtil.validateToken(jwt, userDetails)) {
				HttpSession session = request.getSession(true);
				session.setAttribute("userId", userName);
				ResponseCookie springCookie = ResponseCookie.from("accessToken", token)
						.httpOnly(true)
						//.secure(true)
						.path("/")
						.maxAge(60*60)
						//.domain("example.com")
						.build();
				return ResponseEntity
						.ok()
						.header(HttpHeaders.SET_COOKIE, springCookie.toString())
						.build();
			}
			else {
				@SuppressWarnings("static-access")
				ResponseEntity<String> responseEntity = new ResponseEntity<>(HttpStatus.UNAUTHORIZED).ok("User authentication failed...!!!");
				return responseEntity;
			}
		} catch (Exception ex) {
			log.error("Exception encountered while authenticating user: {}", ex.getMessage(), ex);
		}
		loginController.setLoginFailuare(userId, request);
		System.out.println("before return");
		@SuppressWarnings("static-access")
		ResponseEntity<String> responseEntity = new ResponseEntity<>(HttpStatus.OK).ok("Invalid username/password");
		return responseEntity;
		
	}
}