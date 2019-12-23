package cn.giteasy.bootstrap.controller;

import cn.giteasy.bootstrap.entity.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by Axin in 2019/12/16 22:10
 */
@RestController
public class MediaTypeController {

    /**
     * 根据客户端请求的 Content-Type，响应相应的 UserVO 类型.
     *
     * @return
     */
    @RequestMapping("/user")
    public User getUser() {
        return new User("giteasy", 18);
    }
}
