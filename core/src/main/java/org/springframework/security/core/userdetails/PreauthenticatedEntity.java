/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.userdetails;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.*;
import java.util.function.Function;

/**
 * Models core user information retrieved by a {@link UserDetailsService}.
 * <p>
 * Developers may use this class directly, subclass it, or write their own
 * {@link UserDetails} implementation from scratch.
 * <p>
 * {@code equals} and {@code hashcode} implementations are based on the {@code username}
 * property only, as the intention is that lookups of the same user principal object (in a
 * user registry, for example) will match where the objects represent the same user, not
 * just when all the properties (authorities, password for example) are the same.
 * <p>
 * Note that this implementation is not immutable. It implements the
 * {@code CredentialsContainer} interface, in order to allow the password to be erased
 * after authentication. This may cause side-effects if you are storing instances
 * in-memory and reusing them. If so, make sure you return a copy from your
 * {@code UserDetailsService} each time it is invoked.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class PreauthenticatedEntity implements PreauthenticatedEntityDetails {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private static final Log logger = LogFactory.getLog(PreauthenticatedEntity.class);

	// ~ Instance fields
	// ================================================================================================
	private final String principalName;
	private final Set<GrantedAuthority> authorities;

	// ~ Constructors
	// ===================================================================================================


	/**
	 * Construct the <code>User</code> with the details required by
	 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}.
	 *
	 * @param principalName the username presented to the
	 * <code>DaoAuthenticationProvider</code>
	 * @param authorities the authorities that should be granted to the caller if they
	 * presented the correct username and password and the user is enabled. Not null.
	 *
	 * @throws IllegalArgumentException if a <code>null</code> value was passed either as
	 * a parameter or as an element in the <code>GrantedAuthority</code> collection
	 */
	public PreauthenticatedEntity(String principalName, Collection<? extends GrantedAuthority> authorities) {

		if ((principalName == null) || "".equals(principalName))  {
			throw new IllegalArgumentException(
					"Cannot pass null or empty values to constructor");
		}

		this.principalName = principalName;
		this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
	}

	// ~ Methods
	// ========================================================================================================


	@Override
	public String getPrincipalName() {
		return principalName;
	}
	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	private static SortedSet<GrantedAuthority> sortAuthorities(
			Collection<? extends GrantedAuthority> authorities) {
		Assert.notNull(authorities, "Cannot pass a null GrantedAuthority collection");
		// Ensure array iteration order is predictable (as per
		// UserDetails.getAuthorities() contract and SEC-717)
		SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(
				new AuthorityComparator());

		for (GrantedAuthority grantedAuthority : authorities) {
			Assert.notNull(grantedAuthority,
					"GrantedAuthority list cannot contain any null elements");
			sortedAuthorities.add(grantedAuthority);
		}

		return sortedAuthorities;
	}

	private static class AuthorityComparator implements Comparator<GrantedAuthority>,
			Serializable {
		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		public int compare(GrantedAuthority g1, GrantedAuthority g2) {
			// Neither should ever be null as each entry is checked before adding it to
			// the set.
			// If the authority is null, it is a custom authority and should precede
			// others.
			if (g2.getAuthority() == null) {
				return -1;
			}

			if (g1.getAuthority() == null) {
				return 1;
			}

			return g1.getAuthority().compareTo(g2.getAuthority());
		}
	}

	/**
	 * Returns {@code true} if the supplied object is a {@code User} instance with the
	 * same {@code username} value.
	 * <p>
	 * In other words, the objects are equal if they have the same username, representing
	 * the same principal.
	 */
	@Override
	public boolean equals(Object rhs) {
		if (rhs instanceof PreauthenticatedEntity) {
			return principalName.equals(((PreauthenticatedEntity) rhs).principalName);
		}
		return false;
	}

	/**
	 * Returns the hashcode of the {@code username}.
	 */
	@Override
	public int hashCode() {
		return principalName.hashCode();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString()).append(": ");
		sb.append("Principal Name: ").append(this.principalName).append("; ");

		if (!authorities.isEmpty()) {
			sb.append("Granted Authorities: ");

			boolean first = true;
			for (GrantedAuthority auth : authorities) {
				if (!first) {
					sb.append(",");
				}
				first = false;

				sb.append(auth);
			}
		}
		else {
			sb.append("Not granted any authorities");
		}

		return sb.toString();
	}

	/**
	 * Creates a UserBuilder with a specified user name
	 *
	 * @param principalName the username to use
	 * @return the UserBuilder
	 */
	public static PreauthenticatedEntityBuilder withPrincipalName(String principalName) {
		return builder().principalName(principalName);
	}

	/**
	 * Creates a UserBuilder
	 *
	 * @return the UserBuilder
	 */
	public static PreauthenticatedEntityBuilder builder() {
		return new PreauthenticatedEntityBuilder();
	}



	public static PreauthenticatedEntityBuilder withPreauthenticatedEntityDetails(PreauthenticatedEntityDetails preauthenticatedEntityDetails) {
		return withPrincipalName(preauthenticatedEntityDetails.getPrincipalName())
			.authorities(preauthenticatedEntityDetails.getAuthorities());
	}

	/**
	 * Builds the user to be added. At minimum the username, password, and authorities
	 * should provided. The remaining attributes have reasonable defaults.
	 */
	public static class PreauthenticatedEntityBuilder {
		private String principalName;
		private List<GrantedAuthority> authorities;

		/**
		 * Creates a new instance
		 */
		private PreauthenticatedEntityBuilder() {
		}

		/**
		 * Populates the username. This attribute is required.
		 *
		 * @param principalName the username. Cannot be null.
		 * @return the {@link PreauthenticatedEntityBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public PreauthenticatedEntityBuilder principalName(String principalName) {
			Assert.notNull(principalName, "principalName cannot be null");
			this.principalName = principalName;
			return this;
		}


		/**
		 * Populates the roles. This method is a shortcut for calling
		 * {@link #authorities(String...)}, but automatically prefixes each entry with
		 * "ROLE_". This means the following:
		 *
		 * <code>
		 *     builder.roles("USER","ADMIN");
		 * </code>
		 *
		 * is equivalent to
		 *
		 * <code>
		 *     builder.authorities("ROLE_USER","ROLE_ADMIN");
		 * </code>
		 *
		 * <p>
		 * This attribute is required, but can also be populated with
		 * {@link #authorities(String...)}.
		 * </p>
		 *
		 * @param roles the roles for this user (i.e. USER, ADMIN, etc). Cannot be null,
		 * contain null values or start with "ROLE_"
		 * @return the {@link PreauthenticatedEntityBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public PreauthenticatedEntityBuilder roles(String... roles) {
			List<GrantedAuthority> authorities = new ArrayList<>(
					roles.length);
			for (String role : roles) {
				Assert.isTrue(!role.startsWith("ROLE_"), role
						+ " cannot start with ROLE_ (it is automatically added)");
				authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
			}
			return authorities(authorities);
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user. Cannot be null, or contain
		 * null values
		 * @return the {@link PreauthenticatedEntityBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public PreauthenticatedEntityBuilder authorities(GrantedAuthority... authorities) {
			return authorities(Arrays.asList(authorities));
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user. Cannot be null, or contain
		 * null values
		 * @return the {@link PreauthenticatedEntityBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public PreauthenticatedEntityBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
			this.authorities = new ArrayList<>(authorities);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user (i.e. ROLE_USER, ROLE_ADMIN,
		 * etc). Cannot be null, or contain null values
		 * @return the {@link PreauthenticatedEntityBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public PreauthenticatedEntityBuilder authorities(String... authorities) {
			return authorities(AuthorityUtils.createAuthorityList(authorities));
		}



		public PreauthenticatedEntity build() {
			return new PreauthenticatedEntity(principalName, authorities);
		}
	}
}
