/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.IasXsuaaExchangeBroker;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
//import static org.springframework.http.HttpMethod.PUT;

import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Autowired
	XsuaaTokenFlows xsuaaTokenFlows;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session is created by approuter
			.and()
				.authorizeRequests()
				.antMatchers(GET,"/v1/sayHello").hasAuthority("Read")
                .antMatchers(GET,"/v1/logout").permitAll()
                //.antMatchers(POST, "/api/v1/ads/**").hasAuthority("Update")
                .antMatchers(POST,"/v2/postHello").permitAll()
				.antMatchers(GET,"/v1/*").authenticated()
				.antMatchers(GET,"/v2/*").hasAuthority("Read")
				.antMatchers(GET,"/v3/*").hasAuthority("Read")
				.antMatchers(GET,"/v3/requestRefreshToken/*").hasAuthority("Read")
				.antMatchers(GET,"/health").permitAll()
				.anyRequest().denyAll()
			.and()
				.oauth2ResourceServer()
				.bearerTokenResolver(new IasXsuaaExchangeBroker(xsuaaTokenFlows))
				.jwt()
				.jwtAuthenticationConverter(getJwtAuthenticationConverter());
		// @formatter:on
	}

	/**
	 * Customizes how GrantedAuthority are derived from a Jwt
	 */
	Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

}
