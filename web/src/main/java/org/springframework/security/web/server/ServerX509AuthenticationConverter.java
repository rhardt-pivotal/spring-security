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
package org.springframework.security.web.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.function.Function;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
public class ServerX509AuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

	private static final Log logger = LogFactory.getLog(ServerX509AuthenticationConverter.class);

	private SubjectDnX509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();

	@Override
	public Mono<Authentication> apply(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();
		X509Certificate clientCert = null;
		if (request.getSslInfo() == null || request.getSslInfo().getPeerCertificates() == null ||
			request.getSslInfo().getPeerCertificates().length == 0){
			return Mono.empty();
		}
		else {
			clientCert = request.getSslInfo().getPeerCertificates()[0];
			Object principal = principalExtractor.extractPrincipal(clientCert);
			return Mono.just(new PreAuthenticatedAuthenticationToken(principal, clientCert));
		}
	}

	private byte[] base64Decode(String value) {
		try {
			return Base64.getDecoder().decode(value);
		} catch(Exception e) {
			return new byte[0];
		}
	}

	public void setSubjectPrincipalRegex(String spr) {
		this.principalExtractor.setSubjectDnRegex(spr);
	}

}
