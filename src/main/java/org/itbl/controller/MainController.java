package org.itbl.controller;

import org.itbl.entity.JwtRequest;
import org.itbl.entity.JwtResponse;
import org.itbl.service.CustomUserDetailService;
import org.itbl.utility.JWTUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
	
	@Autowired
	private JWTUtility jwtUtility;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private CustomUserDetailService customUserDetailService;

	@GetMapping("/")
	public String home() {
		
		
		return "home page";
	}
	
	@PostMapping("/authenticate")
	public JwtResponse authenticate(@RequestBody JwtRequest jwtRequest) throws Exception {
		
		try {
			
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(
							jwtRequest.getUsername(), jwtRequest.getPassword()
						)
					);
		}catch (BadCredentialsException e) {
			
			throw new Exception("Invalid Credintial", e);
		}
		
		
		final UserDetails userDetails = customUserDetailService.loadUserByUsername(jwtRequest.getUsername());
		
		final String token = jwtUtility.generateToken(userDetails);
		
		return new JwtResponse(token);
	}
}
