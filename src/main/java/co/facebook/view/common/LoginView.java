package co.facebook.view.common;

import java.awt.AWTException;
import java.awt.Robot;
import java.awt.event.KeyEvent;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.Select;

import co.facebook.ral.DTO.DataDTO;
import co.facebook.utils.Configuracion;

/**
 * @author dilan
 *
 */
public class LoginView {

	WebDriver driver;
	
	@FindBy(css="#email")
	private WebElement emailInput;

	@FindBy(css="#pass")
	private WebElement passInput;
	
	@FindBy(css="#u_0_2")
	private WebElement loginBtn;

	
	
	 public LoginView() {
		driver = Configuracion.iniciarConfiguracionDriverView();
		PageFactory.initElements(driver, this);
	}
	
	
	public  LoginView searchFlight(DataDTO data){
		emailInput.sendKeys("dlsteeven@hotmail.com");
		passInput.sendKeys("no mires mi contraseña :$");
		loginBtn.click();
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return this;
	}

}
