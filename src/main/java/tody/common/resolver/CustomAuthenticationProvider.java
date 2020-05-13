package tody.common.resolver;

import java.util.Collection;

import javax.annotation.Resource;
import javax.security.auth.login.CredentialExpiredException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import tody.common.service.UserService;
import tody.common.vo.CustomUserDetails;

public class CustomAuthenticationProvider implements AuthenticationProvider {
	@Resource(name="userSer")
	private UserService userSer;
	
	@Autowired
	private UserDetailsService userDeSer;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@SuppressWarnings("unchecked")
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = (String) authentication.getPrincipal();
		String password = (String) authentication.getCredentials();
		System.out.println("id : "+ username);
		System.out.println("pw : "+ password);
		
		CustomUserDetails user = (CustomUserDetails) userDeSer.loadUserByUsername(username);
		
		if(!matchPassword(password, user.getPassword())) {
			System.out.println("비번 틀림");
            throw new BadCredentialsException(username); // 비밀번호 불일치 예외
        }

		if (!user.isCredentialsNonExpired()) { // 비밀번호 만료 
			System.out.println("비밀번호 만료");
			throw new CredentialsExpiredException(username); // 비밀번호 만료 예외
		}
			
		if(!user.isEnabled()) { // 계정 활성화
			System.out.println("계정 활성화");
			throw new AuthenticationCredentialsNotFoundException(username); // 인증 요구 거부 예외
		}
		
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) user.getAuthorities();
		System.out.println("권한 확인 완료");
		
		/*
		if(!passwordEncoder.matches(password, user.getPassword())) { // 인코딩
		//	log.debug("matchPassword :::::::: false!");
			System.out.println("불일치");
			throw new BadCredentialsException(username);
		}
		*/
		
		
		return new UsernamePasswordAuthenticationToken(username, password, authorities);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}
	
	private boolean matchPassword(String loginPwd, String password) { // 비밀번호 확인
        return loginPwd.equals(password);
    }


}
