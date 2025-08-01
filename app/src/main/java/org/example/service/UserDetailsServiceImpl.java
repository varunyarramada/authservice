package org.example.service;

import org.example.entities.UserInfo;
import org.example.model.UserInfoDto;
import org.example.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Objects;
import java.util.UUID;

@Component
@AllArgsConstructor
@Data
public class UserDetailsServiceImpl implements UserDetailsService
{

    @Autowired
    private final UserRepository userRepository;

    @Autowired
    private final PasswordEncoder passwordEncoder;


    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {

        log.debug("Entering in loadUserByUsername Method...");
        UserInfo user = userRepository.findByUsername(username);
        if(user == null){
            log.error("Username not found: " + username);
            throw new UsernameNotFoundException("could not found user..!!");
        }
        log.info("User Authenticated Successfully..!!!");
        return new CustomUserDetails(user);
    }

    public UserInfo checkIfUserAlreadyExist(UserInfoDto userInfoDto){
        return userRepository.findByUsername(userInfoDto.getUsername());
    }

    public Boolean signupUser(UserInfoDto userInfoDto){
        /*if (Objects.nonNull(checkIfUserAlreadyExist(userInfoDto))) {
            return false;
        }
        UserInfoDto tempUser=new UserInfoDto();
        tempUser.setUsername(userInfoDto.getUsername());
        tempUser.setPassword(userInfoDto.getPassword());
        if (!checkIfPasswordandEmailValid(tempUser)) {
            return false;
        }
        userInfoDto.setPassword(passwordEncoder.encode(userInfoDto.getPassword()));

        String userId = UUID.randomUUID().toString();
        userRepository.save(new UserInfo(userId, userInfoDto.getUsername(), userInfoDto.getPassword(), new HashSet<>()));
        // pushEventToQueue
        return true;
        */
        //        ValidationUtil.validateUserAttributes(userInfoDto);
        userInfoDto.setPassword(passwordEncoder.encode(userInfoDto.getPassword()));
        if(Objects.nonNull(checkIfUserAlreadyExist(userInfoDto))){
            return false;
        }
        String userId = UUID.randomUUID().toString();
        userRepository.save(new UserInfo(userId, userInfoDto.getUsername(), userInfoDto.getPassword(), new HashSet<>()));
        // pushEventToQueue
        return true;
    }

    public static Boolean checkIfPasswordandEmailValid(UserInfoDto userInfoDto){

        String email=userInfoDto.getEmail();
        String password=userInfoDto.getPassword();

        //String emailRegex="^[A-za-z0-9._%+-]+[A-za-z]+\.[A-za-z]{2,6}$";
        String emailRegex = "^(?i)(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+" +
                "(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c" +
                "\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c" +
                "\\x0e-\\x7f])*\")@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$";
        if(email==null || !email.matches(emailRegex)){
            return false;
        }

        String passwordRegex="^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$%^&+=!]).{8,}$";
        if(password ==null || !password.matches(passwordRegex)){
            return false;
        }

        return true;
    }
}