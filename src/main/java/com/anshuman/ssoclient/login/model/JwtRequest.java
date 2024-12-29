package com.anshuman.ssoclient.login.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
@Getter
@Setter
@NoArgsConstructor	// need default constructor for JSON Parsing
public class JwtRequest implements Serializable {

	@Serial
	private static final long serialVersionUID = 5926468583005150707L;
	
	@JsonProperty("username")
	private String username;

	public JwtRequest(String username) {
		this.setUsername(username);
	}

}
