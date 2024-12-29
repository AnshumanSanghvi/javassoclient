package com.anshuman.ssoclient.model.repository;

import com.anshuman.ssoclient.model.entity.UserMaster;
import org.springframework.stereotype.Repository;

@Repository
public class UserMasterRepositoryImpl implements UserMasterRepository {

    @Override
    public UserMaster findByUserId(String userId) {
        if ("1".equals(userId))
                return new UserMaster("1", "anshuman", "anshuman", "anshuman.sanghvi@gmail.com");
        else return null;
    }

    @Override
    public UserMaster findByUserName(String userName) {
        if ("anshuman".equals(userName))
            return new UserMaster("1", "anshuman", "anshuman", "anshuman.sanghvi@gmail.com");
        else return null;
    }
}
