package co.facebook.bc;

import co.facebook.ral.DTO.DataDTO;
import co.facebook.ral.DTO.ResponseDTO;
import co.facebook.view.PerfilView;
import co.facebook.view.common.LoginView;

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
 * Descripcion del business component.
 * 
 * @author xxxx
 * @version xxx
 * @category business component
 * **/

public class FlightBC {

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
	 * @param loginDTO 
	 * @param xxxx
	 * @return xxxxx (Descriptivo)
	 * 
	 * **/
	
	public static ResponseDTO SearchFlight(DataDTO data){
		try {
			
			LoginView searchUI = new LoginView();
			searchUI.searchFlight(data);
			
			return new ResponseDTO(true,"Transaccion Exitosa");
		} catch (Exception e) {
			return new ResponseDTO(false,e.getMessage());
		}

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
	 * @param loginDTO 
	 * @param xxxx
	 * @return xxxxx (Descriptivo)
	 * 
	 * **/
	
	public static ResponseDTO SelectFlight(DataDTO data){
		try {
			PerfilView flightUI = new PerfilView();
			flightUI.SelectFlight(data);
			
			return new ResponseDTO(true,"Transaccion Exitosa");
		} catch (Exception e) {
			return new ResponseDTO(false,e.getMessage());
		}

	}
	
	
	
	
}
