package p6;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Validator;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

import java.util.Scanner;

/**
 * -v valida.
 * -c canonicaliza.
 * -e codifica con: SQL, HTML, URL.
 */
public class Main {
    // Variables globales
    public static final String VALIDAR = "-v";
    public static final String CANONICALIZAR = "-c";
    public static final String CODIFICAR = "-e";
    public static final String SQL = "SQL";
    public static final String HTML = "HTML";
    public static final String URL = "URL";
    // Opciones elegidas por el usuario
    public static boolean v;
    public static boolean c;
    public static boolean e;
    public static boolean sql;
    public static boolean html;
    public static boolean url;
    // Cadenas de texto tratadas
    static String nombre; static String direccion; static String dni;
    static String tipo; static String numero; static String mes; static String anio; static String cvn;

    public static boolean validar() {
        String contexto = "Validacion";
        try {
            Validator val = ESAPI.validator();
            boolean fallo = false;
            System.out.println("");
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
            System.err.println("Intrusion Exception: " + ex.getMessage());
            return false;
        }
    }

    public static void canonicalizar(){
        Encoder enc = ESAPI.encoder();
        nombre = enc.canonicalize(nombre);
        direccion = enc.canonicalize(direccion);
        dni = enc.canonicalize(dni);
        tipo = enc.canonicalize(tipo);
        numero = enc.canonicalize(numero);
        mes = enc.canonicalize(mes);
        anio = enc.canonicalize(anio);
        cvn = enc.canonicalize(cvn);
    }

    public static void codificar(){
        Encoder enc = ESAPI.encoder();
        System.out.println("\n\n--- Resultados de codificación ---");
        try {
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
            System.err.println("Error al codificar los datos: " + ex.getMessage());
        }
    }

    public static void interaccion(){
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
        if(c){
            canonicalizar();
        }
        boolean validar = true;
        if(v){
            validar = validar();
        }
        if(e && validar){
            codificar();
        } else {
            System.out.println("\nError en validación, se omite la codificación...");
        }
    }

    public static void main(String[] args){
        if(args.length>=0) {
            for (int i = 0; i < args.length; i++) {
                String entrada = args[i].trim();
                if (entrada.equalsIgnoreCase(VALIDAR)) {
                    v = true;
                } else if (entrada.equalsIgnoreCase(CANONICALIZAR)) {
                    c = true;
                } else if (entrada.equalsIgnoreCase(CODIFICAR)) {
                    if (args.length > i+1) {
                        e = true;
                        if(SQL.equalsIgnoreCase(args[i+1].trim())){
                            sql = true;
                        } else if (HTML.equalsIgnoreCase(args[i+1].trim())){
                            html = true;
                        } else if (URL.equalsIgnoreCase(args[i+1].trim())){
                            url = true;
                        } else {
                            System.err.println("Error, opción -e sin tipo correcto especificado.");
                            System.exit(1);
                        }
                        i++;
                    } else {
                        System.err.println("Error, formato erróneo, se debe especificar un parámetro más.");
                        System.exit(1);
                    }
                } else {
                    System.err.println("Error, opción inválida.");
                    System.exit(1);
                }
            }
        } else {
            System.err.println("Error, formato erróneo, se debe especificar un parámetro (como mínimo).");
            System.exit(1);
        }
        // Llamada al metodo principal
        interaccion();
    }
}