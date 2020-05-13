package tody.common.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import tody.common.dao.UserAuthDAO;
import tody.common.vo.CustomUserDetails;

public class CustomUserDetailsService implements UserDetailsService {
	@Autowired
	private UserAuthDAO userAuthDAO;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		CustomUserDetails user = userAuthDAO.getUserById(username);

		if (user == null) { // 유저 정보 존재 여부
			System.out.println("없는 아이디");
			throw new InternalAuthenticationServiceException(username);
		}

		return user;
	}

}
