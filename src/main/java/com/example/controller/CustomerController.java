package com.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("v1")
public class CustomerController {

    //Vamos a inyectar el objeto que definimos en la configuracion para poder acceder a los datos de la sesion
    @Autowired
    private SessionRegistry sessionRegistry;

    @GetMapping("/index")
    public String index(){
        return "Hello World!";
    }

    @GetMapping("/index2")
    public String index2(){
        return "Hello World not secured!";
    }

    //Este controller es para obtener datos de la sesion
    @GetMapping("/session")
    public ResponseEntity<?> getSessionDetails(){

        String sessionId = "";
        //Este objeto User viene definido dentro de Spring Security.
        User userObject = null;

        //Vamos a recuperar los datos de la sesion del usuario
        List<Object> sessions = sessionRegistry.getAllPrincipals(); //Este metodo nos devuelve un listado porque podemos tener multiples personas
                                                                    //logueadas en nuestra aplicacion.

        //Recorremos la lista para recuperar la informacion de el/los usuario/s que se ha/n autenticado
        for (Object session : sessions) {
            if (session instanceof User) {
                userObject = (User) session;
            }
            //Necesitamos recuperar el id de la sesion
            List<SessionInformation> sessionsInformation = sessionRegistry.getAllSessions(session, false); //Enviamos dos parametros: el principal que es el usuario del que queremos recuperar la sesion.
                                                                               //Tambien un boolean, en este caso en false: por ende no incluimos las sesiones ya expiradas.

            //Recorremos la lista de sesiones
            for (SessionInformation sessionInformation : sessionsInformation) {
                //recuperamos el id del usuario que se acaba de autenticar.
                sessionId = sessionInformation.getSessionId();
            }
        }

        //Vamos a retornar los datos como un JSON:
        //Utilizamos un mapa porque al utilizar @RestController automaticamente Spring va a trabajar con la libreria Jackson,
        //la cual se va a encargar de serializar el mapa en un json para que se pueda mostrar en el navegador.
        Map<String, Object> response = new HashMap<>();
        response.put("response", "Hello World");
        response.put("sessionId", sessionId);
        response.put("user", userObject);


        return ResponseEntity.ok(response);
    }

    //se puede configurar seguridad sobre los endpoints

    //cuando me autentico se abre una sesion, por lo cual voy a estar logueado mientras
    //este la sesion abierta.
    //Para cerrar la sesion voy a https://localhost:8080/logout y confirmo el logout. De esa
    //manera se cierra la sesion.
    //Spring Security trae usuario y contraseña por defecto pero no se usan nunca.
    //Para configurar usuario y contraseña lo puedo hacer mediante unas propiedades que se
    //configuran en el application.properties

    //No todas las urls de la app deben tener seguridad. Spring Security por defecto aplica
    //seguridad a toda la aplicacion, nosotros debemos configurar como va a ser esa
    //seguridad.
}
