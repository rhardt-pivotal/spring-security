package org.springframework.security.core.userdetails;

import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;


public class PreauthMapReactiveUserDetailsService extends MapReactiveUserDetailsService implements PreauthReactiveUserDetailsService{

	private String[] defaultAuthorities = new String[]{};
	private String[] defaultRoles = new String[]{};

	public PreauthMapReactiveUserDetailsService(Map<String, UserDetails> users) {
		super(users);
	}

	public PreauthMapReactiveUserDetailsService(UserDetails... users) {
		super(users);
	}

	public PreauthMapReactiveUserDetailsService(Collection<UserDetails> users) {
		super(users);
	}

	@Override
	public Mono<UserDetails> findByUsername(String username) {
		return super.findByUsername(username)
			.switchIfEmpty(defaultUser(username))
			.map(ud -> ud);
	}

	private Mono<UserDetails> defaultUser(String username) {
		return Mono.just(User.builder()
			.accountExpired(false)
			.accountLocked(false)
			.credentialsExpired(false)
			.disabled(false)
			.password("n/a")
			.roles(defaultRoles)
			.authorities(defaultAuthorities)
			.username(username)
			.build());

	}

	public void setDefaultAuthorities(String... defaultAuthorities) {
		this.defaultAuthorities = defaultAuthorities;
	}

	public void setDefaultRoles(String... defaultRoles) {
		this.defaultRoles = defaultRoles;
	}
}
