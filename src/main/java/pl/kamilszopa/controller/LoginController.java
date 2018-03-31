package pl.kamilszopa.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import pl.kamilszopa.auth.AuthHelper;
import pl.kamilszopa.auth.TokenResponse;

@Controller
public class LoginController {

	@RequestMapping(value = "/login", method=RequestMethod.GET)
	public RedirectView login(ModelMap modelMap) {
		String loginUrl = AuthHelper.getLoginUrl();
		 return new RedirectView(loginUrl);
	}
	
	@RequestMapping(value = "/redirect", method=RequestMethod.GET)
	public String getToken(ModelMap modelMap, @RequestParam(value = "code") String code) {
		TokenResponse tokenResponse = AuthHelper.getTokenFromAuthCode(code);
		modelMap.addAttribute("token", tokenResponse.getAccessToken());
		return "home";
	}
	
	
}
