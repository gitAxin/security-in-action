# security-in-action

### 基于角色的权限管理
#### 什么是角色？
- 代表一系列行为或责任的实体
- 限定能做什么、不能做什么
- 用户账号往往与角色相关联

我们在谈到程序权限管理的话，能不能想到角色这一个概念，角色是代表了一系列行为或者责任的实体，用于限制在系统中能做什么，不能做什么，一般来说，一个用户的账号在系统中能做什么，往往取决于这个用户是什么角色，比如一个用户他是一个项目管理员，他就能做这个项目管理员能做的事情，比如说，他可以查看项目中的应用，管理项目组中的成员，可以导出项目报表等等，所以说用户的话关联了角色之后，他就有了一相关角色的一些操作权限 ，所以，角色是一种行为的概念，表示用户能在系统中进行的一些操作。

#### RBAC
- 基于角色的访问控制（Role-Based Access Control）
- 隐式访问控制
```
	if(user.hasRole("Project Manager")){
		//显示按钮
	}else{
		//不显示按钮
	}
```
> 隐式访问控制与角色是密切关联的，假设角色名称改变的话，代码可能也要做相应的改变 
- 显示访问控制
```
	if(user.isPermitted("projectReport:view:12345")){
		//显示按钮
	}else{
		//不显示按钮
	}
```
> 与角色没有直接关联，而是判断是否拥有某种权限，这个权限与角色关联，用户再和角色关联。最终实现用户与权限的关联，这种方式相比隐式访问控制，就比较灵活了。
 
#### 权限管理解决方案
- Apache Shiro
Apache Shiro 相对于SpringSecurity来说，比较轻量级，使用起来比较简单一些
- Spring Security
SpringSecurity在使用上来说比ApacheShiro功能更多一点、更强大一点。在Spring应用中，它是在兼容性以及在支持方面都比Shiro要好一点。Security整个社区也比较完善，发展上前景也比较好。
### SpringSecurity 简介
在JavaEE企业级应用中提供全面的安全服务，特别是在Spring应用中。SpringSecurity经常会做一些集成。SpringSecurity与Apache Shiro其实有很多的相似点。
#### 核心领域概念
- 认证（authentication）:"认证" 是建立主体（principal）的过程。“主体”通常是指可以在应用程序中执行操作的用户、设备或其他系统
- 授权（authorization）:或称为“访问控制（accell-control）”,"授权"是指决定是否允许主体在应用程序中执行一些相关的操作。
#### 身份验证技术
- HTTP BASIC
- HTTP Digest
- HTTP X.509
- LDAP
- 基于表单的认证
- OpenID
- 单点登录
- Remember-Me
- 匿名身份验证
- Run-as
- JAAS
- JavaEE 容器认证
#### 模块
SpringSecurity是模块化的
- Core - spring-security-core.jar:包含认证，授权接口等等
- Remoting- spring-security-remoting.jar
- Web - spring-security-web.jar
- Config - spring-security-config.jar ： 配置
- LDAP - spring-security-ldap.jar
- ACL - spring-security-acl.jar
- CAS - spring-security-cas.jar : 单点登录
- OpenID - spring-security-openid.jar
- Test - spring-security-test.jar
 
### SpringSecurity与SpringBoot集成
#### 依赖

```
	<!-- springboot2.2.2 -->
	<parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.2.2.RELEASE</version>
     </parent>
	
	<!-- springboot已经对thymeleaf做了集成，版本不用写 -->
	<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        
	<!-- springboot已经对security做了集成，版本不用写 -->
	 <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

<!-- 官方并没有对thymeleaf-extras-springsecurity做集成，所以要将此依赖引入进来 -->
	 <dependency>
            <groupId>org.thymeleaf.extras</groupId>
            <artifactId>thymeleaf-extras-springsecurity5</artifactId>
            <version>3.0.4.RELEASE</version>
        </dependency>

```

### SpringSecurity实战
pom.xml

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.2.2.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>cn.giteasy</groupId>
    <artifactId>security-in-action</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>security-in-action</name>
    <description>Demo project for Spring Boot</description>

    <properties>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
            <exclusions>
                <exclusion>
                    <groupId>org.junit.vintage</groupId>
                    <artifactId>junit-vintage-engine</artifactId>
                </exclusion>
            </exclusions>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.thymeleaf.extras</groupId>
            <artifactId>thymeleaf-extras-springsecurity5</artifactId>
            <version>3.0.4.RELEASE</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>

```

创建安全配置类SecurityConfig.java

```
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

```
相应的Controller：MainController.java

```
package cn.giteasy.bootstrap.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 主页控制器
 * Created by Axin in 2019/12/23 21:58
 */
@Controller
public class MainController {

    @GetMapping("/")
    public String root(){
        return "redirect:/index";
    }


    @GetMapping("/index")
    public String index(){
        return "index";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @GetMapping("/login-error")
    public String loginError(Model model){
        model.addAttribute("loginError",true);
        model.addAttribute("errorMsg","登录失败，用户名或密码错误！");
        //登录失败后，还是会返回登录页面，但是会携带错误信息
        return "login";
    }
}

```

前端页面编写：
这里只提供了关键代码，如果需要查看祥细代码，文章结尾有github链接

公共header.html
```
添加命令空间：
<html data-th-fragment="header"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity5">
		......
		......
		......
		......
		 <!--登录判断：如果已登录，显示用户名和退出按钮-->
            <div sec:authorize="isAuthenticated()" class="row">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item">
                      <span class="nav-link" sec:authentication="name"></span>
                    </li>
                </ul>
                <form action="/logout" th:action="@{/logout}" method="post">
                    <input class="btn btn-outline-success" type="submit" value="退出">
                </form>

            </div>
            <!--登录判断：如果未登录，显示登录按钮-->
            <div sec:authorize="isAnonymous()">
                <a href="/login" th:href="@{~/login}" class="btn btn-outline-success my-2 my-sm-0" type="submit">登录</a>
            </div>

			...
			...
			...
</html>
```
index.html

```
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity4">
<head th:replace="~{fragments/header :: header}">
    <!--th:replace="~{fragments/header :: header}"：会将header.html页面内容替换到这个dom节点下-->
</head>
<body>

<div class="container blog-content-container">

    <!--登录判断：如果已登录，显示用户名和用户角色-->
    <div sec:authorize="isAuthenticated()">
        <p>已登录</p>
        <p>用户名：<span sec:authentication="name"></span></p>
        <p>角  色：<span sec:authentication="principal.authorities"></span></p>
    </div>

    <!--登录判断：如果未登录，提示未登录信息-->
    <div sec:authorize="isAnonymous()">
        <p>未登录</p>
    </div>

</div>
<div th:replace="~{fragments/footer :: footer}">...</div>
</body>
</html>
```
login.html

```
		...
		...
		...
	<!--
       /login： 我们并没有在Controller中定义/login接口，
       而在SecurityConfig.java文件中定义了/login接口，
       security会自动拦截登录请求进行匹配账号和密码 进行认证
    -->
    <form action="/login" method="POST" th:action="@{/login}">
        <h3>请登录</h3>
        <div class="from-group col-md-5">
            <label for="username" class="col-form-label">账号</label>
            <input type="text" class="form-control" id="username" name="username" maxlength="50" placeholder="请输入账号">
        </div>
        <div class="from-group col-md-5">
            <label for="password" class="col-form-label">密码</label>
            <input type="text" class="form-control" id="password" name="password" maxlength="50" placeholder="请输入密码">
        </div>
        <div class="from-group col-md-5">
            <button type="submit" class="btn btn-primary">登录</button>
        </div>
        
        <!--登录失败，重定向到此而面，显示登录失败信息-->
        <div class="col-md-5" th:if="${loginError}">
            <p class="blog-label-error" th:text="${errorMsg}"></p>
        </div>
    </form>
		    ...
		    ...
		    ...
    
```
项目目录结构，只标记关键文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191224224615182.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl8zOTU0MTY1Nw==,size_16,color_FFFFFF,t_70)

页面效果

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191224225439124.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl8zOTU0MTY1Nw==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191224225451493.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl8zOTU0MTY1Nw==,size_16,color_FFFFFF,t_70)

>github:https://github.com/gitAxin/security-in-action.git
