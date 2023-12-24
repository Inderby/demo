package com.example.demo;

import jakarta.annotation.security.RolesAllowed;
import java.time.Instant;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtAuthenticationResource {

  JwtEncoder jwtEncoder;

  public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
    this.jwtEncoder = jwtEncoder;
  }

  @GetMapping("/test/{username}")
  @PreAuthorize("hasRole('ROLE_USER') and #username == authentication.name")
  @PostAuthorize("returnObject == 'Hello World'")
  @RolesAllowed({ "ROLE_USER", "ROLE_ADMIN" })
  @Secured({ "ROLE_USER", "ROLE_ADMIN" })
  public String getString(@PathVariable("username") String username) {
    return "Hello World";
  }

  @PostMapping("/authenticate")
  public JwtResponse generateJwtToken(Authentication authentication) {
    return new JwtResponse(createToken(authentication));
  }

  private String createToken(Authentication authentication) {
    var claims = JwtClaimsSet
      .builder()
      .issuer("self")
      .issuedAt(Instant.now())
      .expiresAt(Instant.now().plusSeconds(60 * 15))
      .subject(authentication.getName())
      .claim("scope", createScope(authentication))
      .build();
    JwtEncoderParameters parameters = JwtEncoderParameters.from(claims);
    return jwtEncoder.encode(parameters).getTokenValue();
  }

  private String createScope(Authentication authentication) {
    return authentication
      .getAuthorities()
      .stream()
      .map(a -> a.getAuthority())
      .collect(Collectors.joining(" "));
  }

  public record JwtResponse(String token) {}
}
