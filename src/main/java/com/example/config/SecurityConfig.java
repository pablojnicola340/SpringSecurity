package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
//Debemos indicar que va a ser una clase de configuracion de spring security:
@EnableWebSecurity
public class SecurityConfig {

    //El trabajo de configuracion de nuestro lado puede ser extenso, dado que Spring Security
    //se pone en marcha de entrada al 100% aplicando la seguridad, entonces nosotros tenemos
    //que ir viendo punto por punto las configuraciones que necesitemos explicitar de acuerdo
    //a las necesidades.

    //SecurityFilterChain es una interfaz que utiliza Spring Security para configurar
    //la seguridad.
    //El objeto 'HttpSecurity' es importante. Por defecto ya es un bean en Spring Security
    //que nos ayuda a configurar la seguridad.
    
    /*@Bean
    //PRIMER FORMA DE ESTABLECER LA CONFIGURACION
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        //Aca construimos la configuracion: ESTA ES LA CONFIGURACION MAS BASICA DE SPRING SECURITY.
        return httpSecurity
                //.csrf().disable() --->Cross-Site Request Forgery:
                                       //Es una vulnerabilidad de las aplicaciones web,
                                       //que suele estar presente cuando trabajamos con formularios
                                       //o con un login, por ejemplo.
                                       //Es importante el papel que juega el navegador.
                                       //Esta vulnerabilidad intercepta la comunicacion que esta
                                       //tratando de hacer el navegador a traves del formulario con el
                                       //servidor. Ahi se puede obtener informacion del usuario, acceso a endpoints...etc.
                                       //Por defecto Spring ya nos protege de esta vulnerabilidad. Al poner "disable()"
                                       //estamos inhabilitando esa seguridad. No se recomienda hacer esto en caso de que
                                       //trabajemos con formularios. Se inhabilita en los casos que no tengamos que trabajar
                                       //con formularios directamente desde el navegador.
                                       //En este caso lo dejo comentado porque en el ejemplo se va a trabajar con un formulario,
                                       //por ende quedaria activo.

                .authorizeHttpRequests() //--->Vamos a poder configurar cuales son las URLs que van a estar protegidas
                                         //y cuales no. Por defecto todas estan protegidas.

                    //LO SIGUIENTE PERTENECE A LA CONFIG DE authorizeHttpRequests()
                    .requestMatchers("/v1/index2") //---->Las peticiones que coincidan con los endpoints que mandemos como argumento,
                                                            //los cuales podrian accederse sin ningun tipo de autorizacion.
                        .permitAll() //---->Permitimos a cualquiera que intente consumir ese endpoint el acceso.
                    .anyRequest().authenticated() //----> Indicamos que cualquier otro endpoint tiene que estar autenticado.

                .and()
                .formLogin().permitAll() // --->Indicamos que se les permita a todos acceder al formulario de login.
                .and()
                .httpBasic() // ---> Autenticacion basica: enviariamos nuestro usuario y nuestra constraseña en el header de nuestra peticion
                             //Se puede probar por postman. En la pestaña "Authorization" indico el "type" Basic Auth y al costado
                             //introduzco el Username y el Password, por lo cual ambos se enviarian en el header de la peticion.
                             //Esto se utiliza cuando la seguridad no tiene que ser tan rigurosa.
                .and()
                .build();
    }*/

    //SEGUNDA FORMA DE ESTABLECER LA CONFIGURACION (con funcion lambda --> queda mas resumido si trabajamos con muchas configuraciones)
    @Bean
    public SecurityFilterChain filterChain2(HttpSecurity httpSecurity) throws Exception {
        //Vamos a configurar las mismas propiedades pero de una forma distinta:
        /*return httpSecurity
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/v1/index2").permitAll();
                    auth.anyRequest().authenticated();
                }) //---> podemos enviar una funcion lambda como argumento
                .formLogin().permitAll()
                .and()
                .build();*/

        //Ahora realizamos configuraciones adicionales:
        return httpSecurity
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/v1/index2").permitAll();
                    auth.anyRequest().authenticated();
                }) //---> podemos enviar una funcion lambda como argumento
                .formLogin()
                   .successHandler(successHandler())//---> por ejemplo quiero que el formLogin me redirija a un endpoint especifico.
                                                    //Si la solicitud de inicio de sesion es exitosa me va a redirigir a un endpoint especifico.
                                                    //Como argumento toma un handler que puedo definir mas abajo.
                   .permitAll()
                .and()
                .sessionManagement() //--->Establecemos la configuracion del comportamiento de la sesion
                //La ventaja de trabajar con sesiones es que se puede guardar informacion del usuario, tener un almacenamiento
                //de los datos sin tener que pedirle al usuario volver a autenticarse, entre otras ventajas.

                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) //--->definimos la politica de creacion de sesion
                                                                         //Tenemos opciones:

                                                                         //ALWAYS - va a crear una sesion siempre y cuando no exista ninguna.
                                                                         //Si ya hay una seccion existente la va a reutilizar.

                                                                         //IF_REQUIRED - crea una nueva sesion solo si es necesario. Si la sesion
                                                                         //aun no existe la va a crear. Es mas estricto que el ALWAYS, dado que va
                                                                         //evaluar si es necesario crear una sesion para el usuario que se esta autenticando.

                                                                         //NEVER - no crea ninguna sesion, pero si ya existe una sesion la va a utilizar.

                                                                         //STATELESS - no crea ninguna sesion. Todas las solicitudes las va a trabajar de
                                                                         //forma independiente y no va a guardar ningun dato en sesion.

                    .invalidSessionUrl("/login") //---> Si la sesion es invalida (no se logra crear la sesion, se crea erronea..etc) a donde
                                                 //redirigimos sl usuario? En este caso lo reenviamos al login para que vuelve a intentar autenticarse
                                                 //correctamente por ejemplo.

                    .maximumSessions(1) //---> Cual va a ser el numero maximo de sesiones que va a tener cada usuario. Lo mas comun es que tenga una sola.
                                        //---> Cuando se va a permitir mas de una sesion? En aplicaciones multiplataformas que manejen diferentes flujos de ejecucion,
                                        //aplicaciones de streaming, etc.

                    .expiredUrl("/login") //---> Si el usuario tiene un tiempo, por ejemplo, de 5 minutos permitidos de inactividad, si sobrepasa ese limite y por ende
                                          //se expira la sesion, indicamos la url hacia donde lo vamos a redirigir.

                    //VER LOS DATOS DE LA SESION DEL USUARIO EN TIEMPO REAL (ver los datos que maneja Spring Security de los usuarios autenticados en una sesion)
                    .sessionRegistry(sessionRegistry()) //---> podemos definir o inyectar un objeto que se va a encargar de administrar todos los registros que estan en la sesion.
                                                        //(mas abajo se define un metodo sessionRegistry que retorna el objeto que nos va a ayudar a obtener los datos de la sesion)
                                                        //Mediante esta propiedad estamos habilitando a ese objeto para que haga un rastreo de los datos del usuario autenticado.

                .and()
                .sessionFixation() //--->Vulnerabilidad de aplicaciones web cuando trabajamos con sesiones. Por ejemplo, ingresamos a la aplicacion y nos
                                   //autenticamos correctamente. Un atacante puede usar esta vulnerabilidad y utilizar una sesion de manera indefinida.
                                   //Por ejemplo, cuando iniciamos sesion se genera un ID de sesion. El atacante se apropia de ese ID y ataca a la aplicacion.

                    .migrateSession() // ---->Frente a este escenario podemos utilizar 3 tipos de configuracion:

                                      // - migrateSession: cuando se detecta que se esta tratando de hacer un ataque de fijacion de sesion inmediatamente
                                      //Spring genera otro ID de session. Cuando el atacante intente usar el ID robado no va a poder. Tambien este metodo
                                      //tiene una ventaja: cuando genera el nuevo ID trae todos los datos de la otra sesion, asi el usuario no pierde
                                      //los datos de su sesion.

                                      // - newSession: hace lo mismo que el migrate pero no copia los datos, crea una sesion completamente en blanco.

                                      // - none: es la menos recomendable, inhabilita la seguridad contra la fijacion de sesion.

                .and()
                .build();
    }

    //Defino el handler
    public AuthenticationSuccessHandler successHandler(){
        return ((request, response, authentication) -> {
            response.sendRedirect("/v1/session");
        });
    }

    //Objeto que nos va a ayudar a obtener los datos de la sesion
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }
}
