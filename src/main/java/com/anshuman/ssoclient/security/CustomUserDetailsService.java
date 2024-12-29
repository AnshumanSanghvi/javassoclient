package com.anshuman.ssoclient.security;


import com.anshuman.ssoclient.model.entity.UserMaster;
import com.anshuman.ssoclient.model.repository.UserMasterRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;


@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

	private final UserMasterRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.debug("Loading user by username: {}", username);
		if(username.endsWith("_su")) {
			username=username.replace("_su", "");
		}
		UserMaster user = repository.findByUserName(username);
		
		if(user != null)
			{
				log.debug("User found: {}", user);
				return new org.springframework.security.core.userdetails.User(user.getUserId(), user.getPassword(),
					new ArrayList<>());
			}
		else
			{
				throw new UsernameNotFoundException("User not found with username: " + username);		
			}
	}
}