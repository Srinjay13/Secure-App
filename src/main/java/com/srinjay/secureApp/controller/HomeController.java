package com.srinjay.secureApp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {
	// To use our own password we will need to set the username and password in the application.properties file and to get the data from Postman, we will need to provide the Basic Auth in the Authorization Tab from postman before sending the request
	@RequestMapping("/")
	public String home() {
		return "index.jsp";
	}
}
