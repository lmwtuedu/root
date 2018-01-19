package com.darker.shiro;

import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * 盐值
 */
public class UsernameSaltPasswordToken extends UsernamePasswordToken {
    private String salt;

    public UsernameSaltPasswordToken(String username, String password, String salt) {
        super(username,password);
        this.salt = salt;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
