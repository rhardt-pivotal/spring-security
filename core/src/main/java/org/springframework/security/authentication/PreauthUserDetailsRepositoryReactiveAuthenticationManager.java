package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PreauthReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public class PreauthUserDetailsRepositoryReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final PreauthReactiveUserDetailsService userDetailsService;

	public PreauthUserDetailsRepositoryReactiveAuthenticationManager(PreauthReactiveUserDetailsService userDetailsService) {
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		final String username = authentication.getName();
		return this.userDetailsService.findByUsername(username)
			.publishOn(Schedulers.parallel())
			.switchIfEmpty(  Mono.error(new InternalAuthenticationServiceException("preauth userDetailsService should always return something")) )
			.map( u -> new UsernamePasswordAuthenticationToken(u, u.getPassword(), u.getAuthorities()) );
	}

}
