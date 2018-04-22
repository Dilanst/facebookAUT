package co.facebook.utils;

import org.openqa.selenium.Capabilities;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.DesiredCapabilities;

import ru.stqa.selenium.factory.WebDriverPool;

public class Configuracion {
	
	public static void iniciarConfiguracion(){
		DesiredCapabilities navegador;
		WebDriver driver;
		
		switch (PATH.NAVEGADOR) {
		case CHROME:
			ChromeOptions options = new ChromeOptions();
			options.addArguments("--disable-notifications");
			//Seteo las capabilities del navegador
			navegador =  DesiredCapabilities.chrome();
			navegador.setCapability(ChromeOptions.CAPABILITY, options);
			// crea una nueva instancia
			 System.setProperty("webdriver.chrome.driver", "chromedriver");
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			 driver.get(PATH.URL);
			 break;
		case FIREFOX:
			//Seteo las capabilities del navegador
			navegador = DesiredCapabilities.firefox();
			// crea una nueva instancia
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			 driver.get(PATH.URL);
			break;
		case IE:
			//Seteo las capabilities del navegador
			navegador = DesiredCapabilities.internetExplorer();
			// crea una nueva instancia
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			 driver.get(PATH.URL);
			break;
		default:
			//Seteo las capabilities del navegador
			navegador = DesiredCapabilities.chrome();
			// crea una nueva instancia
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			 driver.get(PATH.URL);
			break;
		}
		
	}
	
	public static WebDriver iniciarConfiguracionDriverView(){
		DesiredCapabilities navegador;
		WebDriver driver;
		
		switch (PATH.NAVEGADOR) {
		case CHROME:
			ChromeOptions options = new ChromeOptions();
			options.addArguments("--disable-notifications");
			//Seteo las capabilities del navegador
			navegador =  DesiredCapabilities.chrome();
			navegador.setCapability(ChromeOptions.CAPABILITY, options);
			// crea una nueva instancia
			 System.setProperty("webdriver.chrome.driver", "chromedriver");
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			 driver.get(PATH.URL);
			 break;
			 case FIREFOX:
			//Seteo las capabilities del navegador
			navegador = DesiredCapabilities.firefox();
			// crea una nueva instancia
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			break;
		case IE:
			//Seteo las capabilities del navegador
			navegador = DesiredCapabilities.internetExplorer();
			// crea una nueva instancia
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			break;
		default:
			//Seteo las capabilities del navegador
			navegador = DesiredCapabilities.chrome();
			// crea una nueva instancia
			 driver = WebDriverPool.DEFAULT.getDriver(navegador);
			break;
		}
		
		return driver;
	}

}
