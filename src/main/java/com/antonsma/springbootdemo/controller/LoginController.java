package com.antonsma.springbootdemo.controller;

import com.antonsma.springbootdemo.bean.User;
import com.antonsma.springbootdemo.dao.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    @Autowired
    UserDao userDao;

    @PostMapping("/api/getUserPassword") // @RequestMapping注解创建接口
    public String userLogin(@RequestBody User user) { // @RequestBody注解方便找到user实体

        System.out.println("User : " + user);
        String str = "error";
        int count = userDao.getUserByMassage(user.getEmail(), user.getPassword());
        if (count > 0) {
            str = "ok";
        }
        return str;
    }
}
