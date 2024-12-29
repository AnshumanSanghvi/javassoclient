package com.anshuman.ssoclient.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserMaster {

    private String userId;
    private String password;
    private String username;
    private String email;

}
