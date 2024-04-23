package com.techsoft.springsecurity.logout;

import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
@Service
public class BlackList {
    private Set<String> blackListTokenSet = new HashSet<>();

    public void blacKListToken(String token){
        blackListTokenSet.add(token);
    }
    public boolean isBlackListed(String token){
        return blackListTokenSet.contains(token);
    }
}
