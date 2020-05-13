package tody.common.vo;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@SuppressWarnings("serial")
public class CustomUserDetails implements UserDetails {
	private String ID;
	private String PASSWORD;
	private String AUTHORITY; // 권한 : admin, user, guest...
	private boolean ENABLED; // 
	private boolean CREDEXPI = true;
	private String NAME;
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() { // 계정이 갖고있는 모든 권한
		ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
		auth.add(new SimpleGrantedAuthority(AUTHORITY));
		return auth;
	}

	@Override
	public String getPassword() {
		return PASSWORD;
	}

	@Override
	public String getUsername() {
		return ID;
	}

	@Override
	public boolean isAccountNonExpired() { // 계정 만료 확인
		return true;
	}

	@Override
	public boolean isAccountNonLocked() { // 계정 잠김 확인
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() { // 비밀번호 만료
		return CREDEXPI;
	}

	@Override
	public boolean isEnabled() { // 계정 활성하ㅗ
		return ENABLED;
	}
	
	public String getNAME() {
		return NAME;
	}

	public void setNAME(String name) {
		NAME = name;
	}

}
