# L3 \- Software security

## Desarrollo

El trabajo consistió en un proyecto compuesto por dos servicios independientes. El primero, vulnapp, consiste en una aplicación web deliberadamente insegura, mientras que el segundo, fixedapp, trata de una versión segura de vulnapp, parcheada con contramedidas a sus principales vulnerabilidades. Cada servicio incluyó su propio Dockerfile, un script init\_db.py para inicializar una base de datos SQLite y el código fuente app.py desarrollado en Flask.

La aplicación vulnerable fue expuesta en <http://localhost:5000> y la parcheada en <http://localhost:5001>.

Los endpoints definidos en cada versión fueron los siguientes:

* vulnapp:

  * Endpoint /ping: usa subprocess.getoutput(f"ping \-c 1 {host}")

  * Endpoint /user: construye la consulta SQL concatenando parámetros

* fixedapp:

  * Endpoint /ping: valida el parámetro host con expresiones regulares para validar solo letras, números, guiones y puntos y ejecuta el comando con subprocess.run(\[...\]), sin shell=True.

  * Endpoint /user: utiliza consultas parametrizadas que separan la estructura SQL de los datos de entrada.

## Pruebas de ataque

### Funcionamiento normal

Las pruebas de uso seguro se realizaron utilizando los comandos:

```shell
http://localhost:5000/user?username=alice
http://localhost:5001/user?username=alice
```

En ambas aplicaciones devolvieron correctamente los datos del usuario “alice”:

![Uso seguro de vulnapp](/lab3/images/vulnSec.png)

![Uso seguro de fixedapp](/lab3/images/fixedSec.png)  

Esto permitió verificar que la lógica de ambas aplicaciones funciona correctamente antes de iniciar las pruebas de ataque.

#### Pruebas de SQL injection

Se utilizó el siguiente payload para las pruebas de SQL injection:

```shell
/user?username='OR'1'='1
```

Entonces, los resultados obtenidos por cada versión fue diferente:

![SQL injection en vulnapp](/lab3/images/vulnSql.png)  

![SQL injection en fixedapp](/lab3/images/fixedSql.png)  

En el caso de vulnapp, se ingresó como parámetro de búsqueda una condición que siempre es verdadera, por lo que devolvió todos los registros en la tabla users. Esto confirma la vulnerabilidad de su implementación.

Por otro lado, debido al uso de consultas parametrizadas, en fixedapp el mismo payload fue tratado como texto literal. Por lo tanto, no se devolvieron registros y el intento fue registrado como sospechoso en los logs.

#### Pruebas de command injection

Por último, para las pruebas de command injection se probaron los siguientes dos comandos:

```shell
/ping?host=127.0.0.1;ls
/ping?host=127.0.0.1&&id
```

Entonces, los resultados por cada versión fueron los siguientes:

![Primera prueba de command injection en vulnapp](/lab3/images/vulnPing1.png)  

![Segunda prueba de command injection en vulnapp (curl)](/lab3/images/fixedPing1.png)  

![Primera prueba de command injection en fixedapp](/lab3/images/vulnPing1.png)  

![Segunda prueba de command injection en fixedapp (curl)](/lab3/images/fixedPing2.png)  

## Mecanismos de detección: Logging e IDS básico

Se implementó un sistema de registro común en ambos servicios, definido en el módulo logging\_utils.py. Cada solicitud genera una entrada con los siguientes campos:

* Dirección IP de origen.

* Endpoint y parámetros.

* User-Agent.

* Timestamp.

* Resultado o tipo de evento (OK, SUSPICIOUS, SQL\_ERROR, BLOCKED, etc.).

Además, se definió un regex heurístico para identificar tokens típicos de inyección (', ", ;, \--, /\*, \*/, &&, |, \\, etc.). Si se detecta alguno, el sistema registra un evento ALERT con el motivo y el parámetro afectado. Entonces, incrementa un contador por IP en segundo plano.

![Registros de fixedapp durante las pruebas](/lab3/images/fixedLogsPing.png)

Además, si el mismo IP supera N\_THRESHOLD intentos dentro de WINDOW\_SECONDS, se bloquea temporalmente por BLOCK\_SECONDS.

## Detección de errores SQL

El sistema también registra excepciones SQL con fragmentos de la consulta y el mensaje de error. Un número elevado de estos eventos indica pruebas de inyección. Durante las pruebas se observaron entradas SQL\_ERROR generadas por payloads malformados, lo que demuestra la capacidad del registro para detectar escaneos activos o errores inducidos.

![Log de registro en SQL injection](/lab3/images/fixedLogsSql.png)

## Técnicas de prevención

A nivel teórico, se analizaron las técnicas más efectivas de prevención contra inyecciones y vulnerabilidades relacionadas:

* **Consultas parametrizadas (Prepared Statements)**: Separan los datos del código SQL, lo que evita que el motor interprete entradas como parte de la consulta. Constituyen la defensa primaria frente a SQL Injection.

* **Uso seguro de APIs del sistema**: Ejecutar comandos mediante listas de argumentos (subprocess.run(\[...\])) y sin shell=True. Esto impide que operadores ;, && o | sean interpretados por el shell.

* **Validación y whitelisting**: Trata de definir explícitamente los formatos válidos para cada parámetro, específicamente por tipo, longitud y patrón. Esta clase de validación positiva es más segura que los bloqueos parciales, llamados blacklist.

* **Principio de Least Privilege**: Propone que la aplicación y la base de datos deben operar con los permisos mínimos necesarios para cumplir sus funciones a cabalidad. De esta forma se reduce el impacto de una potencial explotación.

* **Cifrado y rotación de credenciales**: Las claves, tokens o backups deben almacenarse en forma cifrada y rotarse periódicamente. Estas medidas minimizan la exposición en caso de encontrarse comprometidas.

* Medidas adicionales:

  * **WAF (Web Application Firewall)**: Filtra solicitudes con patrones maliciosos conocidos.

  * **Rate Limiting**: Restringe la frecuencia de peticiones para mitigar escaneos y ataques DoS.

  * **CAPTCHA y MFA**: Añaden capas de autenticación en operaciones sensibles.

  * **Monitoreo centralizado de logs (SIEM)**: Permite correlacionar eventos y automatizar alertas.
