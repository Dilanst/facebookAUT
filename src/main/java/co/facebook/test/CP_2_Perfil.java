package co.facebook.test;

import java.util.ArrayList;

import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import co.facebook.bc.FlightBC;
import co.facebook.ral.DataRAL;
import co.facebook.ral.DTO.DataDTO;
import co.facebook.utils.Configuracion;
import ru.stqa.selenium.factory.WebDriverPool;

/**
 * <pre>
 * Propiedad Intelectual 
 * xxxxxx
 * 
 * Fecha    ID Artefacto       Autor     
 * xxxxx	xxxxxxxxxxxxxxxxx  xxxxx	
 * 
 * </pre>
 * 
 * Descripcion caso de prueba.
 * 
 * @author
 * @version
 * @category Test
 * **/

public class CP_2_Perfil {
	
	ArrayList<DataDTO> dataPool = new ArrayList<DataDTO>();
	
	//Ingresa la configuracion del navegador,la url, y la ruta del archivo de la data
	
	public void setup(){
		Configuracion.iniciarConfiguracion();
		this.dataPool = DataRAL.getFlight();
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
	@Test
	public void perfilTest() {
		setup();
		for (DataDTO dataDTO : dataPool) {
			/*Enviar cada objeto que contiene el escenario*/
			  FlightBC.SelectFlight(dataDTO);
		}

	}

	//Se cierran las sesiones del driver.
	/*@AfterSuite
	public void stopAllDrivers() {
		WebDriverPool.DEFAULT.dismissAll();
	}
*/
}
