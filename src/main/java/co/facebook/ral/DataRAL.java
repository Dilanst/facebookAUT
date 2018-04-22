package co.facebook.ral;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import co.facebook.ral.DTO.DataDTO;
import jxl.Sheet;
import jxl.Workbook;
import jxl.read.biff.BiffException;


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
 * Descripcion del Ral.
 * 
 * @author xxxx
 * @version xxx
 * @category RAl
 * **/

public class DataRAL {



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


	public static  ArrayList<DataDTO> getFlight(){
		ArrayList<DataDTO> listDataDTO = new ArrayList<DataDTO>();
		DataDTO data = new DataDTO();
		data.setLugarPartida("Cali (CLO)");
		data.setLugarLlegada("Bogotá (BOG)");
		data.setPartida("10/05/2018");
		data.setLlegada("20/05/2018");
		
		listDataDTO.add(data);

		return listDataDTO;
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

	public static String validarDato(Sheet hojaExcelDataPool,String campo,int columna){
		try {
			return hojaExcelDataPool.getCell(hojaExcelDataPool.findCell(campo).getColumn(),columna).getContents();

		} catch (Exception e) {

			return "";
		}


	}


}
