package nl.quintor.iamservice.security;

import nl.quintor.iamservice.service.QuserService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class MyUserDetailService implements UserDetailsService {

    private QuserService userService;

    public MyUserDetailService(QuserService userService) {
        this.userService = userService;
    }


    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return userService.findByUsername(s)
                .map(quser -> new User(quser.getUsername(), quser.getPassword(), quser.getRoles()))
                .orElseThrow(() -> new UsernameNotFoundException("Can't find username"));
    }
}
