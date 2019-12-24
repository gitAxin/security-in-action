package cn.giteasy.bootstrap.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 安全配置类
 * Created by Axin in 2019/12/23 21:46
 */
@EnableWebSecurity //启用Security
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 自定义配置
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests()
           .antMatchers("/css/**","/js/**","/fonts/**","/index").permitAll()//都可以访问
           .antMatchers("/users/**").hasRole("ADMIN")//需要ADMIN的角色才能访问
           .and()
           .formLogin()//基于form表单认证
           .loginPage("/login") //自定义登录页面
           .failureUrl("/login-error");//登录失败页面
    }

    /**
     * 认证信息管理
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()//为了演示方便我们将认证信息存储在内存中
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("axin") //用于演示的用户名
                .password(new BCryptPasswordEncoder().encode("123456"))//密码
                .roles("ADMIN");//角色名称
    }
}
