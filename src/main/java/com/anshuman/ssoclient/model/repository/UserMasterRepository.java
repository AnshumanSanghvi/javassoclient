package com.anshuman.ssoclient.model.repository;

import com.anshuman.ssoclient.model.entity.UserMaster;

public interface UserMasterRepository {

    UserMaster findByUserId(String userId);

    UserMaster findByUserName(String userName);
}
