package com.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CustomerController {
	
	@GetMapping("/spring")
	public String showSpring(){
		return "hello-world";
	}
	
	@GetMapping("/")
	public String showHome(){
		return "home";
	}
	
	//add a request for /leaders
	@GetMapping("/leaders")
	public String showLeaders(){
		return "leaders";
	}
	
	//add a request for /system
		@GetMapping("/systems")
		public String showSystems(){
			return "systems";
		}
}