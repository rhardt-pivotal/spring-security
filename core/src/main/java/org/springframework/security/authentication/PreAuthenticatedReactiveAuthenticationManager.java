/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collection;
import java.util.Collections;

/**
 * @author Rob Hardt
 */
public class PreAuthenticatedReactiveAuthenticationManager implements ReactiveAuthenticationManager {
	private ReactiveUserDetailsService userDetailsService;

	private Collection<GrantedAuthority> defaultAuthorities = Collections.emptyList();

	private String NO_PASSWORD = "__NO_PASSWORD__";

	public PreAuthenticatedReactiveAuthenticationManager() {
		super();
	}

	public PreAuthenticatedReactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public Mono<Authentication> authenticate(Authentication authentication) {
		final String username = authentication.getName();
		return this.userDetailsService.findByUsername(username)
				.publishOn(Schedulers.parallel())
				.switchIfEmpty(Mono.just(defaultUser(authentication.getName())))
				.map( u -> new PreAuthenticatedAuthenticationToken(u.getUsername(),
																	u.getPassword(),
																	u.getAuthorities()) );
	}

	private UserDetails defaultUser(String name) {
		return User.builder()
			.authorities(defaultAuthorities)
			.username(name)
			.build();
	}

	public void setDefaultAuthorities(Collection<GrantedAuthority> authorities) {
		this.defaultAuthorities = authorities;
	}

	public void setUserDetailsService(ReactiveUserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
}
