package co.facebook.utils;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

/**
 *Esta clase permite realizar consultas y conexiones a una base de datos 
 *por medio de un archivo JSON.  
 *
 *@author Dilan Steven Mejia Buitrago.
 *@version 0.0.1-SNAPSHOT
 *
 **/


public class ProcessQuery {
	static final Type TYPE_QUERY = new TypeToken<List<Query>>() {
	}.getType();
	
	static final Type TYPE_DB = new TypeToken<List<DataBase>>() {
	}.getType();

	public static void main(String[] args) {
		//Test Cases
		Map<String, String> parametros = new HashMap<String, String>();
		parametros.put("idNombre", "1");
		parametros.put("idApodo", "2");
		
		
		String queryReady = getQuery("D:\\query",parametros,"firstQuery").getNameQuery();
		String conectionDB = getConectionBD("D:\\conection","firstConection").getNameConection();
		
		System.out.println(queryReady+" "+conectionDB);

	}

	/**
	 * Este metodo permite obtener y preparar el query que se va ejecutar 
	 * para la base de datos, el query es sacado de un archivo JSON.
	 * 
	 * @param fileQuery Archivo donde se encuentra el query a ejecutar. 
	 * @param params Parametro o lista de parametros que va recibir el query.
	 * @param queryName Nombre del query.
	 * @param nameBD Nombre de la conexion de la base de datos. 
	 * 
	 **/
	public static Query getQuery(String fileQuery,Map params,String queryName){

		Gson gson = new Gson();
		JsonReader reader;
		String query = "";
		Iterator iterador;
		Query result = null;
		
		try {
			//Leo el archivo JSON
			reader = new JsonReader(new FileReader(fileQuery));
			//Obtengo una lista de arreglos de querys
			List<Query> list = gson.fromJson(reader, TYPE_QUERY);
			
			//Filtro en el archivo por el nombre del query  
			 result =  list.stream()
					.filter(map -> queryName.equals(map.getNameQuery()))
					.findFirst().
					orElse(null);

			//Remplazo las variables en el query	        	
			query = result.getQuery();
			iterador = params.keySet().iterator();
			
			while(iterador.hasNext()){
				String key = (String) iterador.next();
				query = query.replace(":"+key, params.get(key).toString());
			}
			//Se ingresa el query preparado
			result.setQuery(query);
			
		} catch (FileNotFoundException e) {
		}
		
		return result;
	} 
	
	
	/**
	 * Este metodo permite obtener la conexion a la base de datos de un 
	 * archivo JSON.
	 * 
	 * @param fileDB Archivo donde se encuentra la conexion a la base de datos. 
	 * @param nameConection Nombre de la conexion de la base de datos. 
	 * 
	 **/
	
	public static DataBase getConectionBD(String fileDB,String nameConection){
		Gson gson = new Gson();
		JsonReader reader;
		DataBase  result = null ;
		
		try {
			//Leo el archivo JSON
			reader = new JsonReader(new FileReader(fileDB));
			//Obtengo una lista de arreglos de conexiones
			List<DataBase> list = gson.fromJson(reader, TYPE_DB);
			
			//Filtro en el archivo por el nombre del de la conexion  
			result =  list.stream()
					.filter(map -> nameConection.equals(map.getNameConection()))
					.findFirst().
					orElse(null);

		} catch (FileNotFoundException e) {
		}
		
		return result;
	}
	
	
	/**
	 * Permite la conección a una base de datos. 
	 * @param query query ya listo para usar.
	 * @param conectionDB conexión lista para usar.
	 * **/
	private void queryBD(String query,String conectionDB){
		//TODO Aqui va la conexion a la base de datos y la consulta
	} 

	
	
	
	
	

}