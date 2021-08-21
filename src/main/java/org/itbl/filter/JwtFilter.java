package org.itbl.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.itbl.service.CustomUserDetailService;
import org.itbl.utility.JWTUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtFilter extends OncePerRequestFilter{
	
	@Autowired
	private JWTUtility jwtUtility;
	
	@Autowired
	private CustomUserDetailService customUserDetailService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		
		final String authorization = request.getHeader("Authorization");
		
		String token = null;
		String userName = null;
		
		
		// JWT Token is in the form "Bearer token". Remove Bearer word and get
		// only the Token
		if(authorization != null && authorization.startsWith("Bearer ")) {
			token = authorization.substring(7);
			userName = jwtUtility.getUsernameFromToken(token);
		}
		
		// Once we get the token validate it.
		if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = customUserDetailService.loadUserByUsername(userName);
			
			// if token is valid configure Spring Security to manually set
			// authentication
			if (jwtUtility.validateToken(token, userDetails)) {

				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// After setting the Authentication in the context, we specify
				// that the current user is authenticated. So it passes the
				// Spring Security Configurations successfully.
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
			
			filterChain.doFilter(request, response);
		}
		

		
	}

	
}
