package co.facebook.view;

import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.Select;

import co.facebook.ral.DTO.DataDTO;
import co.facebook.utils.Configuracion;

/**
 * 
 * @author dilan
 *
 */

public class PerfilView {

	WebDriver driver;

	@FindBy(css="[href='https://www.facebook.com/dilan.steeven']")
	private List<WebElement> perfilBtn;


	public PerfilView() {
		driver = Configuracion.iniciarConfiguracionDriverView();
		PageFactory.initElements(driver, this);
	}

	/**
	 * <pre>
	 * Propiedad Intelectual 
	 * xxxxxx
	 * 
	 * Fecha    ID Caso de Prueba  Autor     
	 * xxxxx	xxxxxxxxxxxxxxxxx  xxxxx	
	 * 
	 * </pre>
	 * 
	 * Descripcion del metodo.
	 * 
	 * @author xxxx
	 * @param xxxx
	 * @return xxxxx (Descriptivo)
	 * 
	 * **/	

	public PerfilView SelectFlight(DataDTO cuenta){
		
		perfilBtn.get(0).click();
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return this;
	}




}
