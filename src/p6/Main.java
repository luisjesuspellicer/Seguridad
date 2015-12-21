package p6;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Validator;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

import java.util.Scanner;

/**
 * Práctica 6 de Seguridad Informática - Canonicalización, validación y codificación
 *
 * Esta clase principal, es la encargada de realizar tareas de canonicalización, validación y
 * codificación para una serie de datos introducidos a través de un formulario.
 * Para estas tareas, se hace uso de ESAPI (Enterprise Security API), cuya configuración ha
 * sido establecida en el fichero "ESAPI.properties".
 *
 * Autores: Luis Jesús Pellicer Magallón (520256) y Raúl Piracés Alastuey (490790)
 */
public class Main {
    // Variables globales finales
    public static final String VALIDAR = "-v";
    public static final String CANONICALIZAR = "-c";
    public static final String CODIFICAR = "-e";
    public static final String SQL = "SQL";
    public static final String HTML = "HTML";
    public static final String URL = "URL";
    // Opciones elegidas por el usuario por argumentos de invocación
    public static boolean v;
    public static boolean c;
    public static boolean e;
    public static boolean sql;
    public static boolean html;
    public static boolean url;
    // Cadenas de texto tratadas (correspondientes al formulario tratado)
    static String nombre; static String direccion; static String dni;
    static String tipo; static String numero; static String mes; static String anio; static String cvn;

    /**
     * Metodo que valida todas las cadenas de texto recibidas a traves del formulario interactivo con el usuario.
     * Hace uso de la clase Validator de ESAPI, para validar todas las cadenas según unas expresiones regulares,
     * previamente establecidas en el fichero "validation.properties". Informa cuando alguna de estas cadenas falla
     * en su validación.
     * @return boolean true si todas las cadenas se han validado correctamente, false en otro caso.
     */
    public static boolean validar() {
        // Se establece el contexto de la validación (útil para logs)
        String contexto = "Validacion";
        try {
            // Se declara un objeto Validator (ESAPI), para realizar la validación de las cadenas de texto
            Validator val = ESAPI.validator();
            boolean fallo = false;
            System.out.println("");
            /*
             *  Realiza la validación para todos los campos del formulario, indicando cuales de ellos fallan
             *  (si fallan). La validación se realiza mediante las expresiones regulares declaradas en el fichero
             *  "validation.properties".
             */
            if(!val.isValidInput(contexto, nombre, "Name", 50, false)){
                System.out.println("Fallo al validar el campo \"Nombre\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, direccion, "Address", 50, false)){
                System.out.println("Fallo al validar el campo \"Dirección\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, dni, "DNI", 9, false)){
                System.out.println("Fallo al validar el campo \"DNI\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, tipo, "CCType", 4, false)){
                System.out.println("Fallo al validar el campo \"Tipo tarjeta crédito\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, numero, "CCNumber", 16, false)){
                System.out.println("Fallo al validar el campo \"Número tarjeta crédito\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, mes, "CCMonth", 2, false)){
                System.out.println("Fallo al validar el campo \"Mes de expiración tarjeta crédito\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, anio, "CCYear", 4, false)){
                System.out.println("Fallo al validar el campo \"Año de expiración tarjeta crédito\"");
                fallo = true;
            }
            if(!val.isValidInput(contexto, cvn, "CCCVN", 3, false)){
                System.out.println("Fallo al validar el campo \"Código CVN tarjeta crédito\"");
                fallo = true;
            }
            return !fallo;
        } catch (IntrusionException ex){
            // Si se detecta una "intrusión", se avisa al usuario
            System.err.println("Intrusion Exception: " + ex.getMessage());
            return false;
        }
    }

    /**
     * Método que se encarga de canonicalizar todas las cadenas introducidas en el formulario.
     * Convierte las cadenas recibidas como entrada a su forma más simple posible, reduciendo
     * una cadena de caracteres a su forma canónica (representación única).
     * Esta tarea soluciona problemas de diversas representaciones de los mismos datos, que
     * puedan dar lugar a bugs y comportamientos no deseados (así como fallos de seguridad).
     */
    public static void canonicalizar(){
        // Crea una instancia del objeto Encoder (ESAPI)
        Encoder enc = ESAPI.encoder();
        // Canonicaliza todas las cadenas requeridas
        nombre = enc.canonicalize(nombre);
        direccion = enc.canonicalize(direccion);
        dni = enc.canonicalize(dni);
        tipo = enc.canonicalize(tipo);
        numero = enc.canonicalize(numero);
        mes = enc.canonicalize(mes);
        anio = enc.canonicalize(anio);
        cvn = enc.canonicalize(cvn);
    }

    /**
     * Método encargado de realizar las diferentes tareas de codificación.
     * Es posible codificar las cadenas del formulario para SQL (MySQL), HTML y URLs.
     * La codificación para este tipo de formatos, evita posibles errores o fallos de seguridad, al adaptar cada
     * cadena al formato específico de cada codificación. Esto da como lugar una representación de los caracteres de
     * la cadena única, que impide posibles fallos futuros (en su posterior utilización).
     */
    public static void codificar(){
        // Crea una instancia del objeto Encoder (ESAPI)
        Encoder enc = ESAPI.encoder();
        System.out.println("\n\n--- Resultados de codificación ---");
        try {
            // Codificación de tipo SQL (si esta establecido), en concreto MySQL
            if (sql) {
                MySQLCodec codec = new MySQLCodec(MySQLCodec.Mode.STANDARD);
                System.out.println("-- Codificación para MySQL --");
                System.out.println("Nombre: " + enc.encodeForSQL(codec, nombre));
                System.out.println("Dirección: " + enc.encodeForSQL(codec, direccion));
                System.out.println("DNI: " + enc.encodeForSQL(codec, dni));
                System.out.println("Tipo tarjeta crédito: " + enc.encodeForSQL(codec, tipo));
                System.out.println("Número tarjeta crédito: " + enc.encodeForSQL(codec, numero));
                System.out.println("Mes de expiración tarjeta crédito: " + enc.encodeForSQL(codec, mes));
                System.out.println("Año de expiración tarjeta crédito: " + enc.encodeForSQL(codec, anio));
                System.out.println("Código CVN tarjeta crédito: " + enc.encodeForSQL(codec, numero) + "\n");
            }
            // Codificación de tipo HTML (si esta establecido)
            if (html) {
                System.out.println("-- Codificación para HTML --");
                System.out.println("Nombre: " + enc.encodeForHTML(nombre));
                System.out.println("Dirección: " + enc.encodeForHTML(direccion));
                System.out.println("DNI: " + enc.encodeForHTML(dni));
                System.out.println("Tipo tarjeta crédito: " + enc.encodeForHTML(tipo));
                System.out.println("Número tarjeta crédito: " + enc.encodeForHTML(numero));
                System.out.println("Mes de expiración tarjeta crédito: "
                        + enc.encodeForHTML(mes));
                System.out.println("Año de expiración tarjeta crédito: "
                        + enc.encodeForHTML(anio));
                System.out.println("Código CVN tarjeta crédito: "
                        + enc.encodeForHTML(numero) + "\n");
            }
            // Codificación de tipo URL (si esta establecido)
            if (url) {
                System.out.println("-- Codificación para URL --");
                System.out.println("Nombre: " + enc.encodeForURL(nombre));
                System.out.println("Dirección: " + enc.encodeForURL(direccion));
                System.out.println("DNI: " + enc.encodeForURL(dni));
                System.out.println("Tipo tarjeta crédito: " + enc.encodeForURL(tipo));
                System.out.println("Número tarjeta crédito: " + enc.encodeForURL(numero));
                System.out.println("Mes de expiración tarjeta crédito: " + enc.encodeForURL(mes));
                System.out.println("Año de expiración tarjeta crédito: " + enc.encodeForURL(anio));
                System.out.println("Código CVN tarjeta crédito: " + enc.encodeForURL(numero) + "\n");
            }
        } catch(EncodingException ex){
            // Si se produce cualquier error en la codificación, se notifica al usuario
            System.err.println("Error al codificar los datos: " + ex.getMessage());
        }
    }

    /**
     * Método encargado de realizar la interacción con el usuario para el relleno del formulario establecido.
     * Acepta de uno en uno, todos los datos del formulario por la entrada estándar, de forma interactiva
     * (aunque puede ser automatizada). Posteriormente, este mismo método, se encarga de canonicalizar, validar y
     * codificar (en diferentes formatos) según las opciones elegidas por el usuario
     * (contemplando posibles errores en cada tarea).
     */
    public static void interaccion(){
        // Se establece un método de interacción (mediante entrada estandar) con el usuario
        // Mediante la interacción se rellenan todos los campos necesarios del formulario
        Scanner entrada = new Scanner(System.in);
        System.out.println("------ Formulario personal ------");
        System.out.print("Nombre: ");
        nombre = entrada.nextLine();
        System.out.print("Dirección: ");
        direccion = entrada.nextLine();
        System.out.print("DNI: ");
        dni = entrada.nextLine();
        System.out.println("--- Información sobre la tarjeta de crédito ---");
        System.out.print("Tipo: ");
        tipo = entrada.nextLine();
        System.out.print("Número: ");
        numero = entrada.nextLine();
        System.out.print("Mes de expiración: ");
        mes = entrada.nextLine();
        System.out.print("Año de expiración: ");
        anio = entrada.nextLine();
        System.out.print("CVN: ");
        cvn = entrada.nextLine();
        entrada.close();
        System.out.println("------ Fin del formulario personal ------\n");
        // Tareas a realizar
        // Si esta establecido, se realiza la tarea de canonicalización
        if(c){

            canonicalizar();
        }
        boolean validar = true;
        // Si esta establecido, se realiza la tarea de validación
        if(v){
            validar = validar();
        }
        // Si esta establecido, y la validación a sido satisfactoria, se codifican los datos (según lo establecido)
        if(e && validar){
            codificar();
        } else {
            // Si no se produce una validación correcta, se avisa al usuario
            System.out.println("\nError en validación, se omite la codificación...");
        }
    }

    /**
     * Punto de entrada del programa (método principal).
     * Este método, se encarga principalmente de parsear los argumentos de entrada para establecer las tareas a
     * realizar y posteriormente llamar al método encargado de ejecutarlas. Acepta todo tipo de combinaciones de
     * argumentos válidos. Si se detecta un error en la sintaxis de los argumentos, se informa al usuario y se
     * cancela la ejecución del programa.
     *
     * Ejecución: nombrePrograma [-c|-v|-e] (SQL|HTML|URL).
     * Para la opción "-e", siempre debe de preceder el tipo de codificación (SQL, HTML o URL).
     * @param args son los argumentos recibidos en la ejecución del programa.
     */
    public static void main(String[] args){
        // Comprueba el número de argumentos
        if(args.length>=0) {
            // Itera a traves de todos los argumentos pasados, indicando las tareas a realizar por el programa
            for (int i = 0; i < args.length; i++) {
                String entrada = args[i].trim();
                // Reconocimiento de tipo de opción leida
                if (entrada.equalsIgnoreCase(VALIDAR)) {
                    v = true;
                } else if (entrada.equalsIgnoreCase(CANONICALIZAR)) {
                    c = true;
                } else if (entrada.equalsIgnoreCase(CODIFICAR)) {
                    // En el caso de codificación, un argumento extra debe de ser introducido
                    if (args.length > i+1) {
                        e = true;
                        // Reconocimiento de codificación seleccionada
                        if(SQL.equalsIgnoreCase(args[i+1].trim())){
                            sql = true;
                        } else if (HTML.equalsIgnoreCase(args[i+1].trim())){
                            html = true;
                        } else if (URL.equalsIgnoreCase(args[i+1].trim())){
                            url = true;
                        } else {
                            // Codificación no correcta
                            System.err.println("Error, opción -e sin tipo correcto especificado.");
                            System.exit(1);
                        }
                        i++;
                    } else {
                        // Codificación no especificada
                        System.err.println("Error, formato erróneo, se debe especificar un argumento más.");
                        System.exit(1);
                    }
                } else {
                    // Opción no reconocida introducida
                    System.err.println("Error, opción inválida.");
                    System.exit(1);
                }
            }
        } else {
            // Número de argumentos inválido
            System.err.println("Error, formato erróneo, se debe especificar un argumento (como mínimo).");
            System.exit(1);
        }
        // Llamada al metodo principal de interacción y realización de tareas
        interaccion();
    }
}