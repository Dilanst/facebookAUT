

# Las claves criptográficas no deben ser demasiado cortas

Al generar claves criptográficas (o pares de claves), es importante utilizar una longitud de clave que proporcione suficiente entropía contra los ataques de fuerza bruta.

Al generar claves criptográficas (o pares de claves), es importante utilizar una longitud de clave que proporcione suficiente entropía contra los ataques de fuerza bruta.

Esta regla plantea un problema cuando un generador de par de claves RSA se inicializa con un parámetro de longitud demasiado pequeña.

```cs using System;
using System.Security.Cryptography;

namespace MyLibrary
{
    public class MyCryptoClass
    {
        static void Main()
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(1024); // Noncompliant
            // ...
        }
    }
}
```

```cs using System;
using System.Security.Cryptography;

namespace MyLibrary
{
    public class MyCryptoClass
    {
        static void Main()
        {
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048);
            // ...
        }
    }
}
```





# "CoSetProxyBlanket" y "CoInitializeSecurity" no deben utilizarse

CoSetProxyBlanket y CoInitializeSecurity trabajan para establecer el contexto de permisos en el que se ejecuta el proceso invocado inmediatamente después.

Específicamente, estos métodos están destinados a ser llamados desde código no administrado, como un contenedor C ++ que luego invoca el código administrado, es decir, C # o VB.NET.

```cs [DllImport("ole32.dll")]
static extern int CoSetProxyBlanket([MarshalAs(UnmanagedType.IUnknown)]object pProxy, uint dwAuthnSvc, uint dwAuthzSvc,
 [MarshalAs(UnmanagedType.LPWStr)] string pServerPrincName, uint dwAuthnLevel, uint dwImpLevel, IntPtr pAuthInfo,
 uint dwCapabilities);

public enum RpcAuthnLevel
{
 Default = 0,
 None = 1,
 Connect = 2,
 Call = 3,
 Pkt = 4,
 PktIntegrity = 5,
 PktPrivacy = 6
}

public enum RpcImpLevel
{
 Default = 0,
 Anonymous = 1,
 Identify = 2,
 Impersonate = 3,
 Delegate = 4
}

public enum EoAuthnCap
{
 None = 0x00,
 MutualAuth = 0x01,
 StaticCloaking = 0x20,
 DynamicCloaking = 0x40,
 AnyAuthority = 0x80,
 MakeFullSIC = 0x100,
 Default = 0x800,
 SecureRefs = 0x02,
 AccessControl = 0x04,
 AppID = 0x08,
 Dynamic = 0x10,
 RequireFullSIC = 0x200,
 AutoImpersonate = 0x400,
 NoCustomMarshal = 0x2000,
 DisableAAA = 0x1000
}

[DllImport("ole32.dll")]
public static extern int CoInitializeSecurity(IntPtr pVoid, int cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1,
 RpcAuthnLevel level, RpcImpLevel impers, IntPtr pAuthList, EoAuthnCap dwCapabilities, IntPtr pReserved3);

static void Main(string[] args)
{
 var hres1 = CoSetProxyBlanket(null, 0, 0, null, 0, 0, IntPtr.Zero, 0); // Noncompliant

 var hres2 = CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, RpcAuthnLevel.None,
  RpcImpLevel.Impersonate, IntPtr.Zero, EoAuthnCap.None, IntPtr.Zero); // Noncompliant
}
```





# Las consultas SQL no deben ser vulnerables a los ataques de inyección

Los datos proporcionados por el usuario, como los parámetros de URL, siempre deben considerarse como no confiables y contaminados.

Normalmente, la solución es confiar en declaraciones preparadas en lugar de concatenación de cadenas para inyectar datos contaminados en consultas SQL, lo que garantiza que se escaparán correctamente.

```cs public class SqlInjection : Controller
{
  private readonly UsersContext _context;

  public SqlInjection(UsersContext context)
  {
    _context = context;
  }

  // GET /SqlInjection/Authenticate
  public IActionResult Authenticate(string user)
  {
    var query = "SELECT * FROM Users WHERE Username = '" + user + "'"; // Unsafe
    var userExists = _context.Users.FromSql(query).Any(); // Noncompliant

    // An attacker can bypass authentication by setting user to this special value
    user = "' or 1=1 or ''='";

    return Content(userExists ? "success" : "fail");
  }
}
```

```cs public class SqlInjection : Controller
{
  private readonly UsersContext _context;

  public SqlInjection(UsersContext context)
  {
    _context = context;
  }

  // GET /SqlInjection/Authenticate
  public IActionResult Authenticate(string user)
  {
    var query = "SELECT * FROM Users WHERE Username = {0}"; // Safe
    var userExists = _context.Users.FromSql(query, user).Any();
    return Content(userExists ? "success" : "fail");
  }
}
```





# Las expresiones regulares no deben ser vulnerables a los ataques de denegación de servicio

Evaluar expresiones regulares contra cadenas de entrada es potencialmente una tarea extremadamente intensiva en CPU.

La evaluación de las cadenas proporcionadas por el usuario como expresiones regulares abre la puerta a los ataques de denegación de servicio.

```cs public class RegexDoS : Controller
{
  // GET /RegexDoS/Validate
  public IActionResult Validate(string regex, string input)
  {
    // Enables attackers to force the web server to evaluate
    // regex such as "^(a+)+$" on inputs such as "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"

    bool match = Regex.IsMatch(input, regex); // Noncompliant

    return Content("Valid? " + match);
  }
}
```

```cs public class RegexDoS : Controller
{
  // GET /RegexDoS/Validate
  public IActionResult Validate(string regex, string input)
  {
    // Option 1: Use a hardcoded regex
    bool match = Regex.IsMatch(input, "^a+$");

    // Option 2: Set a timeout on the regex's evaluation
    match = new Regex(regex, RegexOptions.None, TimeSpan.FromMilliseconds(100)).IsMatch(input);

    return Content("Valid? " + match);
  }
}
```





# No se debe utilizar DES (Estándar de cifrado de datos) ni DESede (3DES)

Según el Instituto Nacional de Estándares y Tecnología (NIST) de EE. UU., El Estándar de cifrado de datos (DES) ya no se considera seguro:

Adoptado en 1977 para que las agencias federales lo utilicen en la protección de información confidencial y no clasificada, el DES se está retirando porque ya no proporciona la seguridad necesaria para proteger la información del gobierno federal.

Se alienta a las agencias federales a utilizar el Estándar de cifrado avanzado, un algoritmo más rápido y más fuerte aprobado como FIPS 197 en 2001.

Por razones similares, RC2 también debe evitarse.

```cs using (var tripleDES = new TripleDESCryptoServiceProvider()) //Noncompliant
{
  //...
}
```

```cs using (var aes = new AesCryptoServiceProvider())
{
  //...
}
```





# Las expresiones XPath no deben ser vulnerables a los ataques de inyección

Los datos proporcionados por el usuario, como los parámetros de URL, siempre deben considerarse como no confiables y contaminados.

```cs public class XPathInjection : Controller
{
  public XmlDocument doc { get; set; }

  // GET /XPathInjection/Authenticate
  public IActionResult Authenticate(string user, string pass)
  {
    String expression = "/users/user[@name='" + user + "' and @pass='" + pass + "']"; // Unsafe

    // An attacker can bypass authentication by setting user to this special value
    user = "' or 1=1 or ''='";

    return Content(doc.SelectSingleNode(expression) != null ? "success" : "fail"); // Noncompliant
  }
}
```

```cs public class XPathInjection : Controller
{
  public XmlDocument doc { get; set; }

  // GET /XPathInjection/Authenticate
  public IActionResult Authenticate(string user, string pass)
  {
    // Restrict the username and password to letters only
    if (!Regex.IsMatch(user, "^[a-zA-Z]+$") || !Regex.IsMatch(pass, "^[a-zA-Z]+$"))
    {
      return BadRequest();
    }

    String expression = "/users/user[@name='" + user + "' and @pass='" + pass + "']"; // Now safe
    return Content(doc.SelectSingleNode(expression) != null ? "success" : "fail");
  }
}
```





# Las llamadas a funciones de E / S no deben ser vulnerables a los ataques de inyección de ruta

Los datos proporcionados por el usuario, como los parámetros de URL, siempre deben considerarse como no confiables y contaminados.

```cs public class PathTraversal : Controller
{
  // GET /PathTraversal/Authenticate
  public IActionResult Authenticate(string user)
  {
    bool userExists = System.IO.File.Exists("/home/" + user); // Noncompliant

    // If the special value "../bin" is passed as user, authentication is bypassed
    // Indeed, if it passed as a user, the path becomes:
    // /bin
    // which exists on most Linux / BSD / Mac OS distributions

    return Content(userExists ? "success" : "fail");
  }
}
```

```cs public class PathTraversal : Controller
{
  // GET /PathTraversal/Authenticate
  public IActionResult Authenticate(string user)
  {
    // Restrict the username to letters and digits only
    if (!Regex.IsMatch(user, "^[a-zA-Z0-9]+$"))
    {
        return BadRequest();
    }

    bool userExists = System.IO.File.Exists("/home/" + user); // Now safe
    return Content(userExists ? "success" : "fail");
  }
}
```





# Las consultas LDAP no deben ser vulnerables a los ataques de inyección

Los datos proporcionados por el usuario, como los parámetros de URL, siempre deben considerarse como no confiables y contaminados.

Dentro de los nombres LDAP, los caracteres especiales '', '#', '"', '+', ',', ';', '<', '>', '\' and null deben escaparse de acuerdo con RFC 4514

```cs public class LDAPInjection : Controller
{
  public DirectorySearcher ds { get; set; }

  // GET /LDAPInjection/Authenticate
  public IActionResult Authenticate(string user, string pass)
  {
    ds.Filter = "(&(uid=" + user + ")(userPassword=" + pass + "))"; // Noncompliant

    // If the special value "*)(uid=*))(|(uid=*" is passed as user, authentication is bypassed
    // Indeed, if it is passed as a user, the filter becomes:
    // (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
    // as uid=* match all users, it is equivalent to:
    // (|(uid=*)(userPassword=...))
    // again, as uid=* match all users, the filter becomes useless

    return Content(ds.FindOne() != null ? "success" : "fail");
  }
}
```

```cs public class LDAPInjection : Controller
{
  public DirectorySearcher ds { get; set; }

  // GET /LDAPInjection/Authenticate
  public IActionResult Authenticate(string user, string pass)
  {
    // Restrict the username and password to letters only
    if (!Regex.IsMatch(user, "^[a-zA-Z]+$") || !Regex.IsMatch(pass, "^[a-zA-Z]+$"))
    {
      return BadRequest();
    }

    ds.Filter = "(&(uid=" + user + ")(userPassword=" + pass + "))"; // Now safe
    return Content(ds.FindOne() != null ? "success" : "fail");
  }
}
```





# Los comandos del sistema operativo no deben ser vulnerables a los ataques de inyección

Las aplicaciones que ejecutan comandos del sistema operativo o ejecutan comandos que interactúan con el sistema subyacente deben neutralizar los valores provistos externamente en esos comandos.

```cs public class CommandInjection : Controller
{
  // GET /CommandInjection/Run
  public IActionResult Run(string binary)
  {
    // If the value "/sbin/shutdown" is passed as binary and the web server is running as root,
    // then the machine running the web server will be shut down and become unavailable for future requests

    Process p = new Process();
    p.StartInfo.FileName = binary; // Noncompliant
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    string output = p.StandardOutput.ReadToEnd();
    return Content(output);
  }
}
```

```cs public class CommandInjection : Controller
{
  // GET /CommandInjection/Run
  public IActionResult Run(string binary)
  {
    // Restrict to binaries within the current working directory whose name only contains letters
    if (binary == null || !Regex.IsMatch(binary, "^[a-zA-Z]+$"))
    {
      return BadRequest();
    }

    Process p = new Process();
    p.StartInfo.FileName = binary; // Now safe
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    string output = p.StandardOutput.ReadToEnd();
    return Content(output);
  }
}
```





# Las credenciales no deben estar codificadas

Debido a que es fácil extraer cadenas de una aplicación compilada, las credenciales nunca deben ser codificadas.

Las credenciales deben almacenarse fuera del código en un archivo o base de datos de configuración cifrada y fuertemente protegido.

```cs string username = "admin";
string password = "Password123"; // Noncompliant
string usernamePassword  = "user=admin&password=Password123"; // Noncompliant
string usernamePassword2 = "user=admin&" + "password=" + password; // Noncompliant
```

```cs string username = "admin";
string password = GetEncryptedPassword();
string usernamePassword = string.Format("user={0}&password={1}", GetEncryptedUsername(), GetEncryptedPassword());
```





# Las clases deben implementar sus interfaces "ExportAttribute"

En el Modelo de programación atribuida, el atributo de exportación declara que una parte "exporta", o proporciona al contenedor de composición, un objeto que cumple un contrato en particular.

Si el tipo no implementa la interfaz que está exportando, habrá un problema en el tiempo de ejecución (ya sea una excepción de conversión o simplemente un contenedor que no está lleno con el tipo exportado) que conduce a comportamientos / bloqueos inesperados.

La regla plantea un problema cuando una clase no implementa o hereda el tipo declarado en ExportAttribute.

```cs [Export(typeof(ISomeType))]
public class SomeType // Noncompliant; doesn't implement 'ISomeType'.
{
}
```

```cs [Export(typeof(ISomeType))]
public class SomeType : ISomeType
{
}
```





# No se debe utilizar "Thread.Resume" ni "Thread.Suspend"

Thread.Suspend y Thread.Resume pueden dar resultados impredecibles, y ambos métodos han quedado en desuso.

```cs static void Main(string[] args)
{
  // ...
  Thread.CurrentThread.Suspend(); // Noncompliant
  Thread.CurrentThread.Resume(); // Noncompliant
}
```





# "SafeHandle.DangerousGetHandle" no debe llamarse

No es sorprendente que el método SafeHandle.DangerousGetHandle sea peligroso.

```cs static void Main(string[] args)
{
    System.Reflection.FieldInfo fieldInfo = ...;
    SafeHandle handle = (SafeHandle)fieldInfo.GetValue(rKey);
    IntPtr dangerousHandle = handle.DangerousGetHandle();  // Noncompliant
}
```





# Los constructores de excepciones no deben lanzar excepciones.

Puede ser una buena idea plantear una excepción en un constructor si no puede rellenar completamente el objeto en cuestión, pero no en un constructor de excepciones.

```cs class MyException: Exception
{
    public void MyException()
    {
         if (bad_thing)
         {
             throw new Exception("A bad thing happened");  // Noncompliant
          }
    }
}
```





# La herencia de tipos no debe ser recursiva

La recursión es aceptable en los métodos, donde puedes salir de ella.

```cs class C1<T>
{
}
class C2<T> : C1<C2<C2<T>>> // Noncompliant
{
}

...
var c2 = new C2<int>();
```





# "IDisposables" deben ser eliminados

Al escribir código administrado, no tiene que preocuparse por asignar o liberar memoria: el recolector de basura se encarga de ello.

Además, la memoria no es el único recurso del sistema que debe administrarse de manera oportuna: el sistema operativo solo puede manejar tener tantos descriptores de archivos (por ejemplo, FileStream) o sockets (por ejemplo, WebClient) abiertos en un momento dado.

Esta regla rastrea los campos privados y las variables locales de los siguientes tipos IDisponibles, que nunca se eliminan, cierran, asignan alias, devuelven o pasan a otros métodos.

Esta regla rastrea los campos privados y las variables locales de los siguientes tipos IDisponibles, que nunca se eliminan, cierran, asignan alias, devuelven o pasan a otros métodos.

Esta regla rastrea los campos privados y las variables locales de los siguientes tipos IDisponibles, que nunca se eliminan, cierran, asignan alias, devuelven o pasan a otros métodos.

```cs public class ResourceHolder
{
  private FileStream fs; // Noncompliant; Dispose or Close are never called

  public void OpenResource(string path)
  {
    this.fs = new FileStream(path, FileMode.Open);
  }

  public void WriteToFile(string path, string text)
  {
    var fs = new FileStream(path, FileMode.Open); // Noncompliant
    var bytes = Encoding.UTF8.GetBytes(text);
    fs.Write(bytes, 0, bytes.Length);
  }
}
```

```cs public class ResourceHolder : IDisposable
{
  private FileStream fs;

  public void OpenResource(string path)
  {
    this.fs = new FileStream(path, FileMode.Open);
  }

  public void Dispose()
  {
    this.fs.Dispose();
  }

  public void WriteToFile(string path, string text)
  {
    using (var fs = new FileStream(path, FileMode.Open))
    {
      var bytes = Encoding.UTF8.GetBytes(text);
      fs.Write(bytes, 0, bytes.Length);
    }
  }
}
```

Las variables identificables devueltas desde un método o pasadas a otros métodos se ignoran, al igual que los IDisposables locales que se inicializan con otros IDisposables.

```cs public Stream WriteToFile(string path, string text)
{
  var fs = new FileStream(path, FileMode.Open); // Compliant, because it is returned
  var bytes = Encoding.UTF8.GetBytes(text);
  fs.Write(bytes, 0, bytes.Length);
  return fs;
}

public void ReadFromStream(Stream s)
{
  var sr = new StreamReader(s); // Compliant as it would close the underlying stream.
  // ...
}
```





# Las cadenas de formato compuesto no deben conducir a un comportamiento inesperado en el tiempo de ejecución

Debido a que las cadenas de formato compuesto se interpretan en tiempo de ejecución, en lugar de ser validadas por el compilador, pueden contener errores que conducen a comportamientos inesperados o errores de tiempo de ejecución.

```cs s = string.Format("[0}", arg0);
s = string.Format("{{0}", arg0);
s = string.Format("{0}}", arg0);
s = string.Format("{-1}", arg0);
s = string.Format("{0} {1}", arg0);
```

```cs s = string.Format("{0}", 42); // Compliant
s = string.Format("{0,10}", 42); // Compliant
s = string.Format("{0,-10}", 42); // Compliant
s = string.Format("{0:0000}", 42); // Compliant
s = string.Format("{2}-{0}-{1}", 1, 2, 3); // Compliant
s = string.Format("no format"); // Compliant
```

```cs var pattern = "{0} {1} {2}";
var res = string.Format(pattern, 1, 2); // Compliant, not const string are not recognized
```

```cs var array = new int[] {};
var res = string.Format("{0} {1}", array); // Compliant we don't know the size of the array
```





# La recursión no debe ser infinita.

La recursión no debe ser infinita.

```cs int Pow(int num, int exponent)   // Noncompliant; no condition under which pow isn't re-called
{
  num = num * Pow(num, exponent-1);
  return num;  // this is never reached
}

void InternalRecursion(int i)
{
  start:
    goto end;
  end:
    goto start; // Noncompliant; there's no way to break out of this method
}
```

```cs int Pow(int num, int exponent)
{
  if (exponent > 1) // recursion now conditional and stop-able
  {
    num = num * Pow(num, exponent-1);
  }
  return num;
}
```





# Los destructores no deben lanzar excepciones.

Si Finalizar o una anulación de Finalizar lanza una excepción, y el tiempo de ejecución no está alojado en una aplicación que anula la política predeterminada, el tiempo de ejecución finaliza el proceso inmediatamente sin una limpieza elegante (finalmente no se ejecutan los bloques ni los finalizadores).

La regla informa sobre las declaraciones de lanzamiento utilizadas en los finalizadores.

```cs class MyClass
{
    ~MyClass()
    {
        throw new NotImplementedException(); // Noncompliant
    }
}
```

```cs class MyClass
{
    ~MyClass()
    {
        // no throw
    }
}
```





# Las excepciones no deben ser lanzadas desde métodos inesperados.

Se espera que algunos métodos se llamen con precaución, pero se espera que otros, como ToString, "funcionen".

Se plantea un problema cuando se lanza una excepción de cualquiera de los siguientes:

```cs public override string ToString()
{
  if (string.IsNullOrEmpty(Name))
  {
    throw new ArgumentException("...");  // Noncompliant
  }
  //...
```

Se ignora System.NotImplementedException y sus derivados.

System.InvalidOperationException, System.NotSupportedException y System.ArgumentException y sus derivados se ignoran en los accesores de eventos.





# "operator ==" no debe sobrecargarse en los tipos de referencia

Se espera que el uso de == para comparar con objetos haga una comparación de referencia.

```cs public static bool operator== (MyType x, MyType y) // Noncompliant
{
```





# El tipo no debe examinarse en las instancias de "System.Type"

El tipo no debe examinarse en las instancias de "System.Type"

```cs var type = typeof(int);
var ttype = type.GetType(); //Noncompliant, always typeof(System.Type)

var s = "abc";

if (s.GetType().IsInstanceOfType(typeof(string))) //Noncompliant; false
{ /* ... */ }
```

```cs var s = "abc";

if (s.GetType().IsInstanceOfType("ssss"))
{ /* ... */ }
```





# El tipo no debe examinarse en las instancias de "System.Type"

El tipo no debe examinarse en las instancias de "System.Type"

```cs [TestMethod]
void TestNullArg()  // Noncompliant; method is not public
{  /* ... */  }

[TestMethod]
public async void MyIgnoredTestMethod()  // Noncompliant; this is an 'async void' method
{ /* ... */ }

[TestMethod]
public void MyIgnoredGenericTestMethod<T>(T foo)  // Noncompliant; method has generics in its signature
{ /* ... */ }
```

```cs [TestMethod]
public void TestNullArg()
{  /* ... */  }
```

El tipo no debe examinarse en las instancias de "System.Type"

El tipo no debe examinarse en las instancias de "System.Type"





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public class MyClass
{
  void Print(string[] messages) {...}
  void Print(string[] messages, string delimiter = "\n") {...} // Noncompliant; default parameter value is hidden by overload
}

// ...
MyClass myClass = new MyClass();

myClass.Print(new string[3] {"yes", "no", "maybe"});  // which version of Print will be called?
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs private int count;
public int Count
{
  get { return count; }
  set { count = 42; } // Noncompliant
}
```

```cs private int count;
public int Count
{
  get { return count; }
  set { count = value; }
}
```

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public int Count
{
  get { return count; }
  set { throw new InvalidOperationException(); }
}
```

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public class JunkFood
{
  public void DoSomething()
  {
    if (this is Pizza) // Noncompliant
    {
      // ...
    } else if (...
  }
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public class GarbageDisposal
{
  private int Dispose()  // Noncompliant
  {
    // ...
  }
}
```

```cs public class GarbageDisposal : IDisposable
{
  public void Dispose()
  {
    // ...
  }
}
```

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public class GarbageDisposal
{
  private int Grind()
  {
    // ...
  }
}
```

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public class GarbageDisposal  :  IDisposable
{
  protected virtual void Dispose(bool disposing)
  {
    //...
  }
  public void Dispose()
  {
    Dispose(true);
    GC.SuppressFinalize(this);
  }
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public class Program
{
    public void WriteMatrix(int[][] matrix) // Non-Compliant
    {
    }
}
```

```cs public class Matrix
{
    // ...
}

public class Program
{
    public void WriteMatrix(Matrix matrix) // Compliant
    {
    }
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs [TestFixture]
public class SomeClassTest { } // Noncompliant - no test

[TestClass]
public class SomeOtherClassTest { } // Noncompliant - no test
```

```cs [TestFixture]
public class SomeClassTest
{
    [Test]
    public void SomeMethodShouldReturnTrue() { }
}

[TestClass]
public class SomeOtherClassTest
{
    [TestMethod]
    public void SomeMethodShouldReturnTrue() { }
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs if (GetTrue() | GetFalse()) // Noncompliant; both sides evaluated
{
}
```

```cs if (GetTrue() || GetFalse()) // true short-circuit logic
{
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs DirectoryEntry myDirectoryEntry = new DirectoryEntry(adPath);
myDirectoryEntry.AuthenticationType = AuthenticationTypes.None; // Noncompliant

DirectoryEntry myDirectoryEntry = new DirectoryEntry(adPath, "u", "p", AuthenticationTypes.None); // Noncompliant
```

```cs DirectoryEntry myDirectoryEntry = new DirectoryEntry(myADSPath); // Compliant; default DirectoryEntry.AuthenticationType property value is "Secure" since .NET Framework 2.0

DirectoryEntry myDirectoryEntry = new DirectoryEntry(myADSPath, "u", "p", AuthenticationTypes.Secure);
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs HttpCookie myCookie = new HttpCookie("UserSettings");
myCookie.HttpOnly = false; // Noncompliant; explicitly set to false
...
Response.Cookies.Add(myCookie);
```

```cs HttpCookie myCookie = new HttpCookie("UserSettings"); // Noncompliant; the default value of 'HttpOnly' is used (=false)
...
Response.Cookies.Add(myCookie);
```

```cs HttpCookie myCookie = new HttpCookie("UserSettings");
myCookie.HttpOnly = true; // Compliant
...
Response.Cookies.Add(myCookie);
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs string text = "";
try
{
    text = File.ReadAllText(fileName);
}
catch (Exception exc) // Noncompliant
{
}
```

```cs string text = "";
try
{
    text = File.ReadAllText(fileName);
}
catch (Exception exc)
{
    logger.Log(exc);
}
```

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public Task<object> GetFooAsync()
{
    return null; // Noncompliant
}
```

```cs public Task<object> GetFooAsync()
{
    return Task.FromResult<object>(null);
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs [Export(typeof(IFooBar))]
[PartCreationPolicy(CreationPolicy.Shared)]
public class FooBar : IFooBar
{
}

public class Program
{
    public static void Main()
    {
        var fooBar = new FooBar(); // Noncompliant;
    }
}
```

```cs [Export(typeof(IFooBar))]
[PartCreationPolicy(CreationPolicy.Shared)]
public class FooBar : IFooBar
{
}

public class Program
{
    public static void Main()
    {
        var fooBar = serviceProvider.GetService<IFooBar>();
    }
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs class A
{
    private int x;
    private int y;

    public int X
    {
        get { return x; }
        set { x = value; }
    }

    public int Y
    {
        get { return x; }  // Noncompliant: field 'y' is not used in the return value
        set { x = value; } // Noncompliant: field 'y' is not updated
    }
}
```

```cs class A
{
    private int x;
    private int y;

    public int X
    {
        get { return x; }
        set { x = value; }
    }

    public int Y
    {
        get { return y; }
        set { y = value; }
    }
}
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs dynamic d = 5;
var x = d >> 5.4; // Noncompliant
x = d >> null; // Noncompliant
x <<= new object(); // Noncompliant
```





# Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

Las sobrecargas de métodos con valores de parámetros predeterminados no deben solaparse

```cs public void MyLockingMethod()
{
  lock (this) // Noncompliant
  {
    // ...
  }
}
```

```cs private readonly object lockObj = new object();

public void MyLockingMethod()
{
  lock (lockObj)
  {
    // ...
  }
}
```

Documentación de Microsoft: Mejores prácticas de subprocesos administrados





# Documentación de Microsoft: Mejores prácticas de subprocesos administrados

Documentación de Microsoft: Mejores prácticas de subprocesos administrados

Documentación de Microsoft: Mejores prácticas de subprocesos administrados

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

```cs foreach (ZipArchiveEntry entry in archive.Entries)
{
    //  entry.FullName could contain parent directory references ".." and the destinationPath variable could become outside of the desired path
    string destinationPath = Path.GetFullPath(Path.Combine(path, entry.FullName));

    entry.ExtractToFile(destinationPath); // Questionable, extracts the entry in a file

    Stream stream;
    stream = entry.Open(); // Questionable, the entry is about to be extracted
}
```





# Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

```cs using System.Threading;
using System.Security.Permissions;
using System.Security.Principal;
using System.IdentityModel.Tokens;

class SecurityPrincipalDemo
{
    class MyIdentity : IIdentity // Questionable, custom IIdentity implementations should be reviewed
    {
        // ...
    }

    class MyPrincipal : IPrincipal // Questionable, custom IPrincipal implementations should be reviewed
    {
        // ...
    }
    [System.Security.Permissions.PrincipalPermission(SecurityAction.Demand, Role = "Administrators")] // Questionable. The access restrictions enforced by this attribute should be reviewed.
    static void CheckAdministrator()
    {
        WindowsIdentity MyIdentity = WindowsIdentity.GetCurrent(); // Questionable
        HttpContext.User = ...; // Questionable: review all reference (set and get) to System.Web HttpContext.User
        AppDomain domain = AppDomain.CurrentDomain;
        domain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal); // Questionable
        MyIdentity identity = new MyIdentity(); // Questionable
        MyPrincipal MyPrincipal = new MyPrincipal(MyIdentity); // Questionable
        Thread.CurrentPrincipal = MyPrincipal; // Questionable
        domain.SetThreadPrincipal(MyPrincipal); // Questionable

        // All instantiation of PrincipalPermission should be reviewed.
        PrincipalPermission principalPerm = new PrincipalPermission(null, "Administrators"); // Questionable
        principalPerm.Demand();

        SecurityTokenHandler handler = ...;
        // Questionable: this creates an identity.
        ReadOnlyCollection<ClaimsIdentity> identities = handler.ValidateToken(…);
    }

     // Questionable: review how this function uses the identity and principal.
    void modifyPrincipal(MyIdentity identity, MyPrincipal principal)
    {
        // ...
    }
}
```





# Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

```cs using System;
public class C
{
    public void Main()
    {
        Console.In; // Questionable
        var code = Console.Read(); // Questionable
        var keyInfo = Console.ReadKey(...); // Questionable
        var text = Console.ReadLine(); // Questionable
        Console.OpenStandardInput(...); // Questionable
    }
}
```

Esta regla plantea un problema cuando el código maneja los archivos.

```cs using System;
public class C
{
    public void Main()
    {
        Console.ReadKey(...); // Return value is ignored
        Console.ReadLine(); // Return value is ignored
    }
}
```





# Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

Esta regla plantea un problema cuando el código maneja los archivos.

```cs System.Net.Http.HttpClient client;
// All the following are Questionable
client.GetAsync(...);
client.GetByteArrayAsync(...);
client.GetStreamAsync(...);
client.GetStringAsync(...);
client.SendAsync(...);
client.PostAsync(...);
client.PutAsync(...);
client.DeleteAsync(...);


System.Net.WebClient webclient;
// All the following are Questionable, although they may be false positives if the URI scheme is "ftp" or "file"
webclient.Download*(...); // Any method starting with "Download"
webclient.Open*(...); // Any method starting with "Open"
webclient.Upload*(...); // Any method starting with "Upload"

// All the following are Questionable, although they may be false positives if the URI scheme is "ftp" or "file"
System.Net.WebRequest.Create(...);
System.Net.WebRequest.CreateDefault(...);

// The following is always Questionable
System.Net.WebRequest.CreateHttp(...);

// === RestSharp ===
// Questionable, as well as any other instantiation of the RestSharp.IRestRequest interface.
new RestSharp.RestRequest(...);
```





# El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

```cs namespace MyNamespace
{
    class Program
    {
        static void Main(string[] args) // Questionable if there is a reference to "args" in the method.
        {
            string myarg = args[0];
            // ...
        }
    }
}
```





# El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

```cs using System.Net.Sockets;

class TestSocket
{
    public static void Run()
    {
        // Questionable
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        // TcpClient and UdpClient simply abstract the details of creating a Socket
        TcpClient client = new TcpClient("example.com", 80); // Questionable
        UdpClient listener = new UdpClient(80); // Questionable
    }
}
```





# El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

```cs String expression = "/users/user[@name='" + user + "' and @pass='" + pass + "']";
xpathNavigator.Evaluate(expression);  // Questionable. Check if the XPATH expression is safe.
```

El uso de argumentos de línea de comando es sensible a la seguridad

```cs xpathNavigator.Evaluate("/users/user[@name='alice']");
```





# El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad

```cs using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;
using System.IO.Compression;
using System.IO.IsolatedStorage;
using System.IO.MemoryMappedFiles;

// Use interop to call the CreateFile function.
// For more information about CreateFile,
// see the unmanaged MSDN reference library.
[DllImport("kernel32.dll", SetLastError = true, CharSet=CharSet.Unicode)]
static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
uint dwFlagsAndAttributes, IntPtr hTemplateFile);


// Review any static method call of File and Directory
File.Exists("test.txt"); // Questionable
Directory.Exists("test"); // Questionable

// Review any instantiation of FileInfo and DirectoryInfo and check how they are used
new FileInfo("test.txt"); // Questionable
new DirectoryInfo("test"); // Questionable

// Review the creation of SafeFileHandle and how it is used.
SafeFileHandle handle = CreateFile(...) // Questionable
new SafeFileHandle(IntPtr.Zero, false); // Questionable

// Questionable: review the creation of FileStream and other Streams accepting a file path.
new FileStream("test.txt", FileMode.Create);

new StreamWriter("test.txt", ...); // Questionable
new StreamReader("test.txt", ...); // Questionable

// Review those two methods as they create file and directories.
Path.GetTempFileName(); // Questionable
Path.GetTempPath(); // Questionable

new FileSecurity("test.txt", AccessControlSections.All); // Questionable

// Review all calls to static methods of ZipFile as they create file and/or directories
ZipFile.CreateFromDirectory("test.txt", "test.zip"); // Questionable

// Review all calls to static methods of IsolatedStorageFile
IsolatedStorageFile.GetMachineStoreForApplication(); // Questionable

// Review all instantiation of IsolatedStorageFileStream and how they are used
new IsolatedStorageFileStream("test.txt", ...); // Questionable

// Review all Create* and Open* static methods of MemoryMappedFile and how the resulting file is used
MemoryMappedFile.CreateFromFile("test.txt"); // Questionable
```

El uso de argumentos de línea de comando es sensible a la seguridad

El uso de argumentos de línea de comando es sensible a la seguridad





# El uso de argumentos de línea de comando es sensible a la seguridad

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

```cs using System;
using System.Collections;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore;

namespace MvcApp
{
    public class ProgramLogging
    {
        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .ConfigureLogging((hostingContext, logging) => // Questionable
                {
                    // ...
                })
                .UseStartup<StartupLogging>();
    }

    public class StartupLogging
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(logging => // Questionable
            {
                // ...
            });
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            IConfiguration config = null;
            LogLevel level = LogLevel.Critical;
            Boolean includeScopes = false;
            Func<string,Microsoft.Extensions.Logging.LogLevel,bool> filter = null;
            Microsoft.Extensions.Logging.Console.IConsoleLoggerSettings consoleSettings = null;
            Microsoft.Extensions.Logging.AzureAppServices.AzureAppServicesDiagnosticsSettings azureSettings = null;
            Microsoft.Extensions.Logging.EventLog.EventLogSettings eventLogSettings = null;

            // An issue will be raised for each call to an ILoggerFactory extension methods adding loggers.
            loggerFactory.AddAzureWebAppDiagnostics(); // Questionable
            loggerFactory.AddAzureWebAppDiagnostics(azureSettings); // Questionable
            loggerFactory.AddConsole(); // Questionable
            loggerFactory.AddConsole(level); // Questionable
            loggerFactory.AddConsole(level, includeScopes); // Questionable
            loggerFactory.AddConsole(filter); // Questionable
            loggerFactory.AddConsole(filter, includeScopes); // Questionable
            loggerFactory.AddConsole(config); // Questionable
            loggerFactory.AddConsole(consoleSettings); // Questionable
            loggerFactory.AddDebug(); // Questionable
            loggerFactory.AddDebug(level); // Questionable
            loggerFactory.AddDebug(filter); // Questionable
            loggerFactory.AddEventLog(); // Questionable
            loggerFactory.AddEventLog(eventLogSettings); // Questionable
            loggerFactory.AddEventLog(level); // Questionable
            loggerFactory.AddEventSourceLogger(); // Questionable

            IEnumerable<ILoggerProvider> providers = null;
            LoggerFilterOptions filterOptions1 = null;
            IOptionsMonitor<LoggerFilterOptions> filterOptions2 = null;

            LoggerFactory factory = new LoggerFactory(); // Questionable
            new LoggerFactory(providers); // Questionable
            new LoggerFactory(providers, filterOptions1); // Questionable
            new LoggerFactory(providers, filterOptions2); // Questionable
        }
    }
}
```

La configuración de los registradores es sensible a la seguridad.

```cs using System;
using System.IO;
using System.Xml;
using log4net.Appender;
using log4net.Config;
using log4net.Repository;

namespace Logging
{
    class Log4netLogging
    {
        void Foo(ILoggerRepository repository, XmlElement element, FileInfo configFile, Uri configUri, Stream configStream,
        IAppender appender, params IAppender[] appenders) {
            log4net.Config.XmlConfigurator.Configure(repository); // Questionable
            log4net.Config.XmlConfigurator.Configure(repository, element); // Questionable
            log4net.Config.XmlConfigurator.Configure(repository, configFile); // Questionable
            log4net.Config.XmlConfigurator.Configure(repository, configUri); // Questionable
            log4net.Config.XmlConfigurator.Configure(repository, configStream); // Questionable
            log4net.Config.XmlConfigurator.ConfigureAndWatch(repository, configFile); // Questionable

            log4net.Config.DOMConfigurator.Configure(); // Questionable
            log4net.Config.DOMConfigurator.Configure(repository); // Questionable
            log4net.Config.DOMConfigurator.Configure(element); // Questionable
            log4net.Config.DOMConfigurator.Configure(repository, element); // Questionable
            log4net.Config.DOMConfigurator.Configure(configFile); // Questionable
            log4net.Config.DOMConfigurator.Configure(repository, configFile); // Questionable
            log4net.Config.DOMConfigurator.Configure(configStream); // Questionable
            log4net.Config.DOMConfigurator.Configure(repository, configStream); // Questionable
            log4net.Config.DOMConfigurator.ConfigureAndWatch(configFile); // Questionable
            log4net.Config.DOMConfigurator.ConfigureAndWatch(repository, configFile); // Questionable

            log4net.Config.BasicConfigurator.Configure(); // Questionable
            log4net.Config.BasicConfigurator.Configure(appender); // Questionable
            log4net.Config.BasicConfigurator.Configure(appenders); // Questionable
            log4net.Config.BasicConfigurator.Configure(repository); // Questionable
            log4net.Config.BasicConfigurator.Configure(repository, appender); // Questionable
            log4net.Config.BasicConfigurator.Configure(repository, appenders); // Questionable
        }
    }
}
```

La configuración de los registradores es sensible a la seguridad.

```cs namespace Logging
{
    class NLogLogging
    {
        void Foo(NLog.Config.LoggingConfiguration config) {
            NLog.LogManager.Configuration = config; // Questionable, this changes the logging configuration.
        }
    }
}
```

La configuración de los registradores es sensible a la seguridad.

```cs namespace Logging
{
    class SerilogLogging
    {
        void Foo() {
            new Serilog.LoggerConfiguration(); // Questionable
        }
    }
}
```





# La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

```cs using System.Security.Cryptography;

void ComputeHash()
{
    // Review all instantiations of classes that inherit from HashAlgorithm, for example:
    HashAlgorithm hashAlgo = HashAlgorithm.Create(); // Questionable
    HashAlgorithm hashAlgo2 = HashAlgorithm.Create("SHA1"); // Questionable
    SHA1 sha = new SHA1CryptoServiceProvider(); // Questionable
    MD5 md5 = new MD5CryptoServiceProvider(); // Questionable
    // ...
}

class MyHashAlgorithm : HashAlgorithm // Questionable
{
    // ...
}
```





# La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

```cs using System;
using System.Security.Cryptography;

namespace MyNamespace
{
    public class MyClass
    {
        public void Main()
        {
            Byte[] data = {1,1,1};

            RSA myRSA = RSA.Create();
            RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(HashAlgorithmName.SHA1);
            // Review all base RSA class' Encrypt/Decrypt calls
            myRSA.Encrypt(data, padding); // Questionable
            myRSA.EncryptValue(data); // Questionable
            myRSA.Decrypt(data, padding); // Questionable
            myRSA.DecryptValue(data); // Questionable

            RSACryptoServiceProvider myRSAC = new RSACryptoServiceProvider();
            // Review the use of any TryEncrypt/TryDecrypt and specific Encrypt/Decrypt of RSA subclasses.
            myRSAC.Encrypt(data, false); // Questionable
            myRSAC.Decrypt(data, false); // Questionable
            int written;
            myRSAC.TryEncrypt(data, Span<byte>.Empty, padding, out written); // Questionable
            myRSAC.TryDecrypt(data, Span<byte>.Empty, padding, out written); // Questionable

            byte[] rgbKey = {1,2,3};
            byte[] rgbIV = {4,5,6};
            SymmetricAlgorithm rijn = SymmetricAlgorithm.Create();
            // Review the creation of Encryptors from any SymmetricAlgorithm instance.
            rijn.CreateEncryptor(); // Questionable
            rijn.CreateEncryptor(rgbKey, rgbIV); // Questionable
            rijn.CreateDecryptor(); // Questionable
            rijn.CreateDecryptor(rgbKey, rgbIV); // Questionable
        }

        public class MyCrypto : System.Security.Cryptography.AsymmetricAlgorithm // Questionable
        {
            // ...
        }

        public class MyCrypto2 : System.Security.Cryptography.SymmetricAlgorithm // Questionable
        {
            // ...
        }
    }
}
```





# La configuración de los registradores es sensible a la seguridad.

La configuración de los registradores es sensible a la seguridad.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

```cs using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace N
{
    public class RegularExpression
    {
        void Foo(string pattern, RegexOptions options, TimeSpan matchTimeout, string input,
                 string replacement, MatchEvaluator evaluator)
        {
            // All the following instantiations are Questionable. Validate the regular expression and matched input.
            new System.Text.RegularExpressions.Regex(pattern);
            new System.Text.RegularExpressions.Regex(pattern, options);
            new System.Text.RegularExpressions.Regex(pattern, options, matchTimeout);

            // All the following static methods are Questionable.
            System.Text.RegularExpressions.Regex.IsMatch(input, pattern);
            System.Text.RegularExpressions.Regex.IsMatch(input, pattern, options);
            System.Text.RegularExpressions.Regex.IsMatch(input, pattern, options, matchTimeout);

            System.Text.RegularExpressions.Regex.Match(input, pattern);
            System.Text.RegularExpressions.Regex.Match(input, pattern, options);
            System.Text.RegularExpressions.Regex.Match(input, pattern, options, matchTimeout);

            System.Text.RegularExpressions.Regex.Matches(input, pattern);
            System.Text.RegularExpressions.Regex.Matches(input, pattern, options);
            System.Text.RegularExpressions.Regex.Matches(input, pattern, options, matchTimeout);

            System.Text.RegularExpressions.Regex.Replace(input, pattern, evaluator);
            System.Text.RegularExpressions.Regex.Replace(input, pattern, evaluator, options);
            System.Text.RegularExpressions.Regex.Replace(input, pattern, evaluator, options, matchTimeout);
            System.Text.RegularExpressions.Regex.Replace(input, pattern, replacement);
            System.Text.RegularExpressions.Regex.Replace(input, pattern, replacement, options);
            System.Text.RegularExpressions.Regex.Replace(input, pattern, replacement, options, matchTimeout);

            System.Text.RegularExpressions.Regex.Split(input, pattern);
            System.Text.RegularExpressions.Regex.Split(input, pattern, options);
            System.Text.RegularExpressions.Regex.Split(input, pattern, options, matchTimeout);
        }
    }
}
```

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.





# Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Las expresiones regulares están sujetas a diferentes tipos de vulnerabilidades.

Reduce el daño que el comando puede hacer:

Reduce el daño que el comando puede hacer:

```cs using System.Security;
using System.Diagnostics;

namespace N
{
    class A
    {
        public void Foo(string fileName, string arguments, string userName, SecureString password, string domain,
                        ProcessStartInfo startInfo, Process process)
        {
            Process.Start(fileName); // Questionable
            Process.Start(fileName, arguments); // Questionable
            Process.Start(fileName, userName, password, domain); // Questionable
            Process.Start(fileName, arguments, userName, password, domain); // Questionable

            Process.Start(startInfo); // Ok, the ProcessStartInfo's FileName has already been highlighted elsewhere

            startInfo.FileName = fileName; // Questionable
            process.StartInfo.FileName = fileName; // Questionable. StartInfo is a ProcessStartInfo.

            new ProcessStartInfo(fileName); // Questionable
            new ProcessStartInfo(fileName, arguments); // Questionable
        }
    }
}
```





# Exponer los puntos finales HTTP es sensible a la seguridad

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

La exposición de los puntos finales HTTP es sensible a la seguridad.

Restrinja las acciones sensibles a la seguridad, como la carga de archivos, a los usuarios autenticados.

Tenga cuidado cuando los errores se devuelven al cliente, ya que pueden proporcionar información confidencial.

```cs public class Foo : System.Web.Mvc.Controller
{
    public string MyProperty
    {
        get { return "test"; }
        set { }
    }
    public Foo() { }

    public void PublicFoo() // Questionable. Public Controller methods are exposed as HTTP endpoints.
    {
        // ...
    }
    [System.Web.Mvc.NonAction]
    public void NotAnEndpoint() // This is not an endpoint because of the NonAction attribute.
    { }
    protected void ProtectedFoo() { }
    internal void InternalFoo() { }
    private void PrivateFoo() { }
    private class Bar : System.Web.Mvc.Controller
    {
        public void InnerFoo() { }
    }
}
```





# Tenga cuidado cuando los errores se devuelven al cliente, ya que pueden proporcionar información confidencial.

Tenga cuidado cuando los errores se devuelven al cliente, ya que pueden proporcionar información confidencial.

Tenga cuidado cuando los errores se devuelven al cliente, ya que pueden proporcionar información confidencial.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace mvcApp
{
    public class Startup2
    {
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                // The following calls are ok because they are disabled in production
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            // Those calls are Questionable because it seems that they will run in production
            app.UseDeveloperExceptionPage(); // Questionable
            app.UseDatabaseErrorPage(); // Questionable
        }
    }
}
```

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.





# Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs using System.Reflection;

Type dynClass = Type.GetType("MyInternalClass");
// Questionable. Using BindingFlags.NonPublic will return non-public members
BindingFlags bindingAttr = BindingFlags.NonPublic | BindingFlags.Static;
MethodInfo dynMethod = dynClass.GetMethod("mymethod", bindingAttr);
object result = dynMethod.Invoke(dynClass, null);
```





# Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs var random = new Random(); // Questionable use of Random
byte[] data = new byte[16];
random.NextBytes(data);
return BitConverter.ToString(data); // Check if this value is used for hashing or encryption
```

```cs using System.Security.Cryptography;
...
var randomGenerator = RandomNumberGenerator.Create(); // Compliant for security-sensitive use cases
byte[] data = new byte[16];
randomGenerator.GetBytes(data);
return BitConverter.ToString(data);
```





# Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs public void Foo(DbContext context, string query)
{
    context.Database.ExecuteSqlCommand(query); // Questionable
    context.Query<User>().FromSql(query); // Questionable
}

public void Bar(SqlConnection connection, string query)
{
    SqlCommand command;
    command = new SqlCommand(query); // Questionable

    command.CommandText = query; // Questionable

    SqlDataAdapter adapter;
    adapter = new SqlDataAdapter(query, connection); // Questionable
}
```

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs public void Foo(DbContext context, string query, string value, params object[] parameters)
{
    context.Database.ExecuteSqlCommand("SELECT * FROM mytable"); // No issue raised. The query is hard-coded. Thus no injection is possible.


    context.Database.ExecuteSqlCommand($"SELECT * FROM mytable WHERE mycol={value}"); // No issue raised. The FormattableString is transformed into a parametrized query.
    // However these need to be reviewed
    context.Database.ExecuteSqlCommand($"SELECT * FROM mytable WHERE mycol={value}", parameters); // Questionable, the FormattableString is evaluated and converted to RawSqlString
    string query = $"SELECT * FROM mytable WHERE mycol={value}"
    context.Database.ExecuteSqlCommand(query); // Questionable, the FormattableString has already been evaluated, it won't be converted to a parametrized query.
}
```





# Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs using System;
using System.Reflection;

class TestReflection
{
    public static void Run(string typeName, string methodName, string fieldName, string propertyName, string moduleName)
    {
        Assembly.Load(...); // Questionable
        Assembly.LoadFile(...); // Questionable
        Assembly.LoadFrom(...); // Questionable
        Assembly.LoadWithPartialName(...); // Questionable + deprecated

        Assembly.ReflectionOnlyLoad(...);  // This is OK as the resulting type is not executable.
        Assembly.ReflectionOnlyLoadFrom(...); // This is OK as the resulting type is not executable.

        Assembly assembly = typeof(TestReflection).Assembly;

        // Review this code to make sure that the module, type, method and field are safe
        Type type = assembly.GetType(typeName); // Questionable
        Module module = assembly.GetModule(moduleName); // Questionable

        type = System.Type.GetType(typeName); // Questionable
        type = type.GetNestedType(typeName); // Questionable
        type = type.GetInterface(typeName);  // Questionable
        MethodInfo method = type.GetMethod(methodName); // Questionable
        FieldInfo field = type.GetField(fieldName); // Questionable
        PropertyInfo property = type.GetProperty(propertyName); // Questionable


        // Review this code to make sure that the modules, types, methods and fields are used safely
        Module[] modules = assembly.GetModules(); // Questionable
        modules = assembly.GetLoadedModules(); // Questionable

        Type[] types = assembly.GetTypes(); // Questionable
        types = assembly.GetExportedTypes(); // Questionable

        types = type.GetNestedTypes(); // Questionable
        MethodInfo[] methods = type.GetMethods(); // Questionable
        FieldInfo[] fields = type.GetFields(); // Questionable
        PropertyInfo[] properties = type.GetProperties(); // Questionable
        MemberInfo[] members = type.GetMembers(); // Questionable
        members = type.GetMember(methodName); // Questionable
        members = type.GetDefaultMembers(); // Questionable

        type.InvokeMember(...); // Questionable, when the method name is provided as a string

        assembly.CreateInstance(typeName); // Questionable


        type = Type.ReflectionOnlyGetType(typeName,true, true); // This is OK as the resulting type is not executable.

        Activator.CreateComInstanceFrom(...); // Questionable, when the type name is provided as a string
        Activator.CreateInstance(...); // Questionable, when the type name is provided as a string
        Activator.CreateInstanceFrom(...); // Questionable, when the type name is provided as a string
        Activator.CreateInstance<>(); // OK - can only be created from a referenced type
    }
}
```

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs assembly.GetType("MyHardcodedType")
```

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs typeof(CustomType).GetMethods();
```





# Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

Usted está en riesgo si responde afirmativamente a cualquiera de estas preguntas.

```cs partial class Point
{
  partial void MoveVertically(int z);
}

partial class Point
{
  int x = 0;
  int y = 0;
  int z = 0;

  partial void MoveVertically(int y)  // Noncompliant
  {
    this.y = y;
  }
}

interface IFoo
{
  void Bar(int i);
}

class Foo : IFoo
{
  void Bar(int z) // Noncompliant, parameter name should be i
  {
  }
}
```

```cs partial class Point
{
  partial void MoveVertically(int z);
}

partial class Point
{
  int x = 0;
  int y = 0;
  int z = 0;

  partial void MoveVertically(int z)
  {
    this.z = z;
  }
}

interface IFoo
{
  void Bar(int i);
}

class Foo : IFoo
{
  void Bar(int i)
  {
  }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs switch (param)
{
    case 0:
      DoSomething();
      break;
    default: // default clause should be the first or last one
      Error();
      break;
    case 1:
      DoSomethingElse();
      break;
}
```

```cs switch (param)
{
    case 0:
      DoSomething();
      break;
    case 1:
      DoSomethingElse();
      break;
    default:
      Error();
      break;
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs using System;

namespace MyLibrary
{
  class Foo
  {
    internal void SomeMethod(string s1, string s2) { }
  }

  class Bar : Foo
  {
    internal void SomeMethod(string s1, object o2) { }  // Noncompliant
  }
}
```

```cs using System;

namespace MyLibrary
{
  class Foo
  {
    internal void SomeMethod(string s1, string s2) { }
  }

  class Bar : Foo
  {
    internal void SomeOtherMethod(string s1, object o2) { }
  }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public void SomeMethod(int count) { }
  }
  public class Bar:Foo
  {
    private void SomeMethod(int count) { } // Noncompliant
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public void SomeMethod(int count) { }
  }
  public sealed class Bar : Foo
  {
    private void SomeMethod(int count) { }
  }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs using System;
using System.Threading;

namespace MyLibrary
{
  class Foo
  {
    string myString = "foo";

    void Bar()
    {
      lock(myString) { } // Noncompliant
    }
  }
}
```

```cs using System;
using System.Threading;

namespace MyLibrary
{
  class Foo
  {
    string myString = "foo";
    private readonly Object thisLock = new Object();

    void Bar()
    {
      lock(thisLock) { } // Compliant
    }
  }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs if (condition)  // Noncompliant
DoTheThing();

DoTheOtherThing();
SomethingElseEntirely();

Foo();
```

```cs if (condition)
  DoTheThing();

DoTheOtherThing();
SomethingElseEntirely();

Foo();
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs if (condition1) {
  // ...
} if (condition2) {  // Noncompliant
  //...
}
```

```cs if (condition1) {
  // ...
} else if (condition2) {
  //...
}
```

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs if (condition1) {
  // ...
}

if (condition2) {
  //...
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs using (Stream stream = new FileStream("file.txt", FileMode.OpenOrCreate))
{
    using (StreamWriter writer = new StreamWriter(stream))  // Noncompliant: 'stream' will be disposed twice
    {
        // Use the writer object...
    }
}
```

```cs Stream stream = null;
try
{
    stream = new FileStream("file.txt", FileMode.OpenOrCreate);
    using (StreamWriter writer = new StreamWriter(stream))
    {
        stream = null;
        // Use the writer object...
    }
}
finally
{
    if(stream != null)
        stream.Dispose();
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs using System;
using System.Reflection;

[assembly: AssemblyTitle("MyAssembly")] // Noncompliant

namespace MyLibrary
{
}
```

```cs using System;
using System.Reflection;

[assembly: AssemblyTitle("MyAssembly")]
[assembly: AssemblyVersionAttribute("1.2.125.0")]

namespace MyLibrary
{
}
```

Las cláusulas "predeterminadas" deberían ser la primera o la última





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs internal class MyException : Exception   // Noncompliant
{
  // ...
}
```

```cs public class MyException : Exception
{
  // ...
}
```

Las cláusulas "predeterminadas" deberían ser la primera o la última





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs class Base
{
  public virtual void Method(int[] numbers)
  {
    ...
  }
}
class Derived : Base
{
  public override void Method(params int[] numbers) // Noncompliant, method can't be called with params syntax.
  {
    ...
  }
}
```

```cs class Base
{
  public virtual void Method(int[] numbers)
  {
    ...
  }
}
class Derived : Base
{
  public override void Method(int[] numbers)
  {
    ...
  }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs class MyClass
{
    public void DoStuff([Optional][DefaultValue(4)]int i, int j = 5)  // Noncompliant
    {
        Console.WriteLine(i);
    }

    public static void Main()
    {
        new MyClass().DoStuff(); // prints 0
    }
}
```

```cs class MyClass
{
    public void DoStuff([Optional][DefaultParameterValue(4)]int i, int j = 5)
    {
        Console.WriteLine(i);
    }

    public static void Main()
    {
        new MyClass().DoStuff(); // prints 4
    }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

Las cláusulas "predeterminadas" deberían ser la primera o la última

```cs class MyClass
{
    public void DoStuff([Optional] ref int i) // Noncompliant
    {
        Console.WriteLine(i);
    }

    public static void Main()
    {
        new MyClass().DoStuff(); // This doesn't compile, CS7036 shows
    }
}
```

```cs class MyClass
{
  public void DoStuff(ref int i)
  {
    Console.WriteLine(i);
  }

  public static void Main()
  {
    var i = 42;
    new MyClass().DoStuff(ref i);
  }
}
```





# Las cláusulas "predeterminadas" deberían ser la primera o la última

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs enum Permissions
{
  None = 0,
  Read = 1,
  Write = 2,
  Execute = 4
}
// ...

var x = Permissions.Read | Permissions.Write;  // Noncompliant; enum is not marked with [Flags]
```

```cs [Flags]
enum Permissions
{
  None = 0,
  Read = 1,
  Write = 2,
  Execute = 4
}
// ...

var x = Permissions.Read | Permissions.Write;
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs class Outer
{
  public static int A;

  public class Inner
  {
    public int A; //Noncompliant
    public int MyProp
    {
      get { return A; }  // Returns inner A. Was that intended?
    }
  }
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs class Outer
{
  public static int A;

  public class Inner
  {
    public int B;
    public int MyProp
    {
      get { return A; }  // Still compiles and runs but functionality has changed
    }
  }
}
```

```cs class Outer
{
  public static int A;

  public class Inner
  {
    public int InnerA;
    public int MyProp
    {
      get { return InnerA; }
    }
  }
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs public class Fruit { }
public class Orange : Fruit { }
public class Apple : Fruit { }

class MyTest
{
  public void Test()
  {
    var fruitBasket = new List<Fruit>();
    fruitBasket.Add(new Orange());
    fruitBasket.Add(new Orange());
    // fruitBasket.Add(new Apple());  // uncommenting this line will make both foreach below throw an InvalidCastException

    foreach (Fruit fruit in fruitBasket)
    {
      var orange = (Orange)fruit; // This "explicit" conversion is hidden within the foreach loop below
      ...
    }

    foreach (Orange orange in fruitBasket) // Noncompliant
    {
      ...
    }
  }
}
```

```cs var fruitBasket = new List<Orange>();
fruitBasket.Add(new Orange());
fruitBasket.Add(new Orange());
// fruitBasket.Add(new Apple());  // uncommenting this line won't compile

foreach (Orange orange in fruitBasket)
{
  ...
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs var fruitBasket = new List<Fruit>();
fruitBasket.Add(new Orange());
fruitBasket.Add(new Orange());
fruitBasket.Add(new Apple());

foreach (Orange orange in fruitBasket.OfType<Orange>())
{
  ...
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs public class MyClass
{
  private static int count = 0;

  public void DoSomething()
  {
    //...
    count++;  // Noncompliant
  }
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs string color = "blue";
string name = "ishmael";

List<string> strings = new List<string>();
strings.Add(color);
strings.Add(name);
string[] stringArray = strings.ToArray();

if (strings.IndexOf(color) > 0) // Noncompliant
{
  // ...
}
if (name.IndexOf("ish") > 0) // Noncompliant
{
  // ...
}
if (name.IndexOf("ae") > 0) // Noncompliant
{
  // ...
}
if (Array.IndexOf(stringArray, color) > 0) // Noncompliant
{
  // ...
}
```

```cs string color = "blue";
string name = "ishmael";

List<string> strings = new List<string> ();
strings.Add(color);
strings.Add(name);
string[] stringArray = strings.ToArray();

if (strings.IndexOf(color) > -1)
{
  // ...
}
if (name.IndexOf("ish") >= 0)
{
  // ...
}
if (name.Contains("ae"))
{
  // ...
}
if (Array.IndexOf(stringArray, color) >= 0)
{
  // ...
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs private List<string> _foo = new List<string> { "a", "b", "c" };
public IEnumerable<string> Foo  // Noncompliant
{
    get
    {
        return _foo.ToList();
    }
}

private string[] _bar = new string[] { "a", "b", "c" };
public IEnumerable<string> Bar // Noncompliant
{
    get
    {
        return (string[])_bar.Clone();
    }
}
```

```cs private List<string> _foo = new List<string> { "a", "b", "c" };
private string[] _bar = new string[] { "a", "b", "c" };

public IEnumerable<string> GetFoo()
{
    return _foo.ToList();
}

public IEnumerable<string> GetBar()
{
    return (string[])_bar.Clone();
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs [Flags]
enum FruitType
{
    Void = 0,        // Non-Compliant
    Banana = 1,
    Orange = 2,
    Strawberry = 4
}
```

```cs [Flags]
enum FruitType
{
    None = 0,        // Compliant
    Banana = 1,
    Orange = 2,
    Strawberry = 4
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs void Add(List<int> list)
{
  int d = unchecked(list.Sum());  // Noncompliant

  unchecked
  {
    int e = list.Sum();  // Noncompliant
  }
}
```

```cs void Add(List<int> list)
{
  int d = list.Sum();

  try
  {
    int e = list.Sum();
  }
  catch (System.OverflowException e)
  {
    // exception handling...
  }
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs void Add(List<int> list)
{
  unchecked
  {
    try
    {
      int e = list.Sum();
    }
    catch (System.OverflowException e)
    {
      // exception handling...
    }
  }
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs abstract class Car
{
  public virtual event EventHandler OnRefueled; // Noncompliant

  public void Refuel()
  {
    // This OnRefueld will always be null
     if (OnRefueled != null)
     {
       OnRefueled(this, null);
     }
  }
}

class R2 : Car
{
  public override event EventHandler OnRefueled;
}

class Program
{
  static void Main(string[] args)
  {
    var r2 = new R2();
    r2.OnRefueled += new EventHandler((o, a) =>
    {
      Console.WriteLine("This event will never be called");
    });
    r2.Refuel();
  }
}
```

```cs abstract class Car
{
  public event EventHandler OnRefueled; // Compliant

  public void Refuel()
  {
    if (OnRefueled != null)
    {
      OnRefueled(this, null);
    }
  }
}

class R2 : Car {}

class Program
{
  static void Main(string[] args)
  {
    var r2 = new R2();
    r2.OnRefueled += new EventHandler((o, a) =>
    {
      Console.WriteLine("This event will be called");
    });
    r2.Refuel();
  }
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs public class Math
{
  public static double Pi = 3.14;  // Noncompliant
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs public class Shape
{
  public static Shape Empty = new EmptyShape();  // Noncompliant

  private class EmptyShape : Shape
  {
  }
}
```

```cs public class Math
{
  public const double Pi = 3.14;
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs public class Shape
{
  public static readonly Shape Empty = new EmptyShape();

  private class EmptyShape : Shape
  {
  }
}
```





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

```cs public interface IMyInterface
{ /* ... */ }

public class Implementer : IMyInterface
{ /* ... */ }

public class MyClass
{ /* ... */ }

public static class Program
{
  public static void Main()
  {
    var myclass = new MyClass();
    var x = (IMyInterface) myclass; // Noncompliant, InvalidCastException is being thrown
    var b = myclass is IMyInterface; // Noncompliant, always false

    int? i = null;
    var ii = (int)i; // Noncompliant, InvalidOperationException is being thrown
  }
}
```

```cs public interface IMyInterface
{ /* ... */ }

public class Implementer : IMyInterface
{ /* ... */ }

public class MyClass
{ /* ... */ }

public static class Program
{
  public static void Main()
  {
    var myclass = new MyClass();
    var x = myclass as IMyInterface; // Compliant, but will always be null
    var b = false;

    int? i = null;
    if (i.HasValue)
    {
      var ii = (int)i;
    }
  }
}
```

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.





# Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Las enumeraciones se usan generalmente para identificar elementos distintos en un conjunto de valores.

Por ejemplo:

```cs public class Parent
{
  public Parent()
  {
    DoSomething();  // Noncompliant
  }

  public virtual void DoSomething() // can be overridden
  {
    ...
  }
}

public class Child : Parent
{
  private string foo;

  public Child(string foo) // leads to call DoSomething() in Parent constructor which triggers a NullReferenceException as foo has not yet been initialized
  {
    this.foo = foo;
  }

  public override void DoSomething()
  {
    Console.WriteLine(this.foo.Length);
  }
}
```





# Por ejemplo:

Por ejemplo:

Por ejemplo:

Por ejemplo:

```cs static void Main(string[] args)
{
  // ...
  GC.Collect(2, GCCollectionMode.Optimized); // Noncompliant
}
```





# Por ejemplo:

Por ejemplo:

```cs public override void DoSomething()
{
}

public override void DoSomethingElse()
{
}
```

```cs public override void DoSomething()
{
  // Do nothing because of X and Y.
}

public override void DoSomethingElse()
{
  throw new NotSupportedException();
}
```

Por ejemplo:





# Por ejemplo:

Por ejemplo:

```cs try
{
  /* some work which end up throwing an exception */
  throw new ArgumentException();
}
finally
{
  /* clean up */
  throw new InvalidOperationException();       // Noncompliant; will mask the ArgumentException
}
```

```cs try
{
  /* some work which end up throwing an exception */
  throw new ArgumentException();
}
finally
{
  /* clean up */                       // Compliant
}
```





# Por ejemplo:

Por ejemplo:

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs public class Base
{
  public virtual void Write(int i = 42)
  {
    Console.WriteLine(i);
  }
}

public class Derived : Base
{
  public override void Write(int i = 5) // Noncompliant
  {
    Console.WriteLine(i);
  }
}

public class Program
{
  public static void Main()
  {
    var derived = new Derived();
    derived.Write(); // writes 5
    Print(derived);  // writes 42; was that expected?
  }
  private void Print(Base item)
  {
    item.Write();
  }
}
```

```cs public class Base
{
  public virtual void Write(int i = 42)
  {
    Console.WriteLine(i);
  }
}

public class Derived : Base
{
  public override void Write(int i = 42)
  {
    Console.WriteLine(i);
  }
}

public class Program
{
  public static void Main()
  {
    var derived = new Derived();
    derived.Write(); // writes 42
    Print(derived);  // writes 42
  }
  private void Print(Base item)
  {
    item.Write();
  }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs using System;
using System.Security;

namespace MyLibrary
{

    [SecurityCritical]
    public class Foo
    {
        [SecuritySafeCritical] // Noncompliant
        public void Bar()
        {
        }
    }
}
```

```cs using System;
using System.Security;

namespace MyLibrary
{

    [SecurityCritical]
    public class Foo
    {
        public void Bar()
        {
        }
    }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs [PartCreationPolicy(CreationPolicy.Any)] // Noncompliant
public class FooBar : IFooBar
{
}
```

```cs [Export(typeof(IFooBar))]
[PartCreationPolicy(CreationPolicy.Any)]
public class FooBar : IFooBar
{
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs using System;

namespace myLibrary
{
  public class MyExtension : MarkupExtension
  {
    public MyExtension() { }

    public MyExtension(object value1)
    {
      Value1 = value1;
    }

    [ConstructorArgument("value2")]
    public object Value1 { get; set; }
  }
}
```

```cs using System;

namespace myLibrary
{
  public class MyExtension : MarkupExtension
  {
    public MyExtension() { }

    public MyExtension(object value1)
    {
      Value1 = value1;
    }

    [ConstructorArgument("value1")]
    public object Value1 { get; set; }
  }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs using System;
using System.Windows.Forms;

namespace MyLibrary
{
    public class MyForm: Form
    {
        public MyForm()
        {
            this.Text = "Hello World!";
        }

        public static void Main()  // Noncompliant
        {
            var form = new MyForm();
            Application.Run(form);
        }
    }
}
```

```cs using System;
using System.Windows.Forms;

namespace MyLibrary
{
    public class MyForm: Form
    {
        public MyForm()
        {
            this.Text = "Hello World!";
        }

        [STAThread]
        public static void Main()
        {
            var form = new MyForm();
            Application.Run(form);
        }
    }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs list[index] = "value 1";
list[index] = "value 2";  // Noncompliant

dictionary.Add(key, "value 1");
dictionary[key] = "value 2"; // Noncompliant
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs if (x < 0)
{
  new ArgumentException("x must be nonnegative");
}
```

```cs if (x < 0)
{
  throw new ArgumentException("x must be nonnegative");
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs if(collection.Count >= 0){...}

if(enumerable.Count() < 0){...}

if(array.Length >= 0){...}

bool result = array.Length >=0;
```

```cs if (list.Any()) { ... }

if (list.Count > 0) { ... }

if (array.Length >= 42) { ... }
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs [Serializable]
public class Foo
{
    [OnSerializing]
    public void OnSerializing(StreamingContext context) {} // Noncompliant should be private

    [OnSerialized]
    int OnSerialized(StreamingContext context) {} // Noncompliant should return void

    [OnDeserializing]
    void OnDeserializing() {} // Noncompliant should have a single parameter of type StreamingContext

    [OnSerializing]
    public void OnSerializing2<T>(StreamingContext context) {} // Noncompliant should have no type parameters

    [OnDeserialized]
    void OnDeserialized(StreamingContext context, string str) {} // Noncompliant should have a single parameter of type StreamingContext
}
```

```cs [Serializable]
public class Foo
{
    [OnSerializing]
    private void OnSerializing(StreamingContext context) {}

    [OnSerialized]
    private void OnSerialized(StreamingContext context) {}

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) {}

    [OnDeserialized]
    private void OnDeserialized(StreamingContext context) {}
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs [Serializable]
public class Foo
{
    [OptionalField(VersionAdded = 2)]
    int optionalField = 5;
}
```

```cs [Serializable]
public class Foo
{
    [OptionalField(VersionAdded = 2)]
    int optionalField = 5;

    [OnDeserializing]
    void OnDeserializing(StreamingContext context)
    {
     optionalField = 5;
    }

    [OnDeserialized]
    void OnDeserialized(StreamingContext context)
    {
        // Set optionalField if dependent on other deserialized values.
    }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs if (b == 0)  // Noncompliant
{
    DoTheThing();
}
else
{
    DoTheThing();
}

int b = a > 12 ? 4 : 4;  // Noncompliant

switch (i) // Noncompliant
{
    case 1:
        DoSomething();
        break;
    case 2:
        DoSomething();
        break;
    case 3:
        DoSomething();
        break;
    default:
        DoSomething();
}
```

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs if (b == 0)    //no issue, this could have been done on purpose to make the code more readable
{
    DoSomething();
}
else if (b == 1)
{
    DoSomething();
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs public class Foo // Noncompliant
{
}

public struct Bar // Noncompliant
{
}
```

```cs namespace SomeSpace
{
    public class Foo
    {
    }

    public struct Bar
    {
    }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs int? nullable = null;
...
UseValue(nullable.Value); // Noncompliant
```

```cs int? nullable = null;
...
if (nullable.HasValue)
{
  UseValue(nullable.Value);
}
```

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs int? nullable = null;
...
if (nullable != null)
{
  UseValue(nullable.Value);
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs int? nullable = 42;
bool comparison = nullable.GetType() == typeof(Nullable<int>); // Noncompliant, always false
comparison = nullable.GetType() != typeof(Nullable<int>); // Noncompliant, always true

nullable = null;
comparison = nullable.GetType() != typeof(Nullable<int>); // Noncompliant, calling GetType on a null always throws an exception
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs class Person
{
  private int age;
  [Pure] // Noncompliant. In this case the method makes a possibly visible state change
  void ConfigureAge(int age)
  {
    ...
    this.age = age;
  }
  ...
}
```

```cs class Person
{
  private int age;

  void ConfigureAge(int age)
  {
    ...
    this.age = age;
  }
  ...
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs [ServiceContract]
interface IMyService
{
  [OperationContract(IsOneWay = true)]
  int SomethingHappened(int parameter); // Noncompliant
}
```

```cs [ServiceContract]
interface IMyService
{
  [OperationContract(IsOneWay = true)]
  void SomethingHappened(int parameter);
}
```

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs public class BaseClass
{
    public virtual void MyMethod(int i = 1)
    {
        Console.WriteLine(i);
    }
}

public class DerivedClass : BaseClass
{
    public override void MyMethod(int i = 1)
    {
        // ...
        base.MyMethod(); // Noncompliant; caller's value is ignored
    }

    static int Main(string[] args)
    {
        DerivedClass dc = new DerivedClass();
        dc.MyMethod(12);  // prints 1
    }
}
```

```cs public class BaseClass
{
    public virtual void MyMethod(int i = 1)
    {
        Console.WriteLine(i);
    }
}

public class DerivedClass : BaseClass
{
    public override void MyMethod(int i = 1)
    {
        // ...
        base.MyMethod(i);
    }

    static int Main(string[] args)
    {
        DerivedClass dc = new DerivedClass();
        dc.MyMethod(12);  // prints 12
    }
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs public class MyClass // Noncompliant
{
  private MyClass() { ... }
}
```

```cs public class MyClass
{
  public MyClass() { ... }
}
```

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs Debug.Assert(list.Remove("dog"));
```

```cs bool result = list.Remove("dog");
Debug.Assert(result);
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs void TraceMessage([CallerMemberName] string memberName = "",
  [CallerFilePath] string filePath = "",
  [CallerLineNumber] int lineNumber = 0,
  string message = null)  // Noncompliant
{
  /* ... */
}
```

```cs void TraceMessage(string message = null,
  [CallerMemberName] string memberName = "",
  [CallerFilePath] string filePath = "",
  [CallerLineNumber] int lineNumber = 0)
{
  /* ... */
}
```





# Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs class MyClass
{
  public static int X = Y; // Noncompliant; Y at this time is still assigned default(int), i.e. 0
  public static int Y = 42;
}
```

```cs class MyClass
{
  public static int Y = 42;
  public static int X = Y;
}
```

Los valores de parámetros predeterminados son inútiles en implementaciones de interfaz explícitas, porque el tipo estático del objeto siempre será la interfaz implementada.

```cs class MyClass
{
  public static int X;
  public static int Y = 42;

  static MyClass()
  {
    X = Y;
  }
}
```





# Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

```cs public class Point
{
  private readonly int x;
  public MyClass(int x)
  {
    this.x = x;
  }
  public override int GetHashCode()
  {
    return x.GetHashCode() ^ base.GetHashCode(); //Noncompliant
  }
}
```

```cs public class Point
{
  private readonly int x;
  public MyClass(int x)
  {
    this.x = x;
  }
  public override int GetHashCode()
  {
    return x.GetHashCode();
  }
}
```

Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

```cs public class Point
{
  public override bool Equals(object obj)
  {
    if (base.Equals(obj)) // Compliant, although it could be replaced with object.ReferenceEquals(obj, this), which is clearer
    {
      return true;
    }
    ...
  }
}
```





# Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

```cs listView.PreviewTextInput += (obj,args) =>
        listView_PreviewTextInput(obj,args,listView);

// ...

listView.PreviewTextInput -= (obj, args) =>
        listView_PreviewTextInput(obj, args, listView); // Noncompliant; this delegate was never subscribed
```

```cs EventHandler func = (obj,args) => listView_PreviewTextInput(obj,args,listView);

listView.PreviewTextInput += func;

// ...

listView.PreviewTextInput -= func;
```





# Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

Las clases que extienden directamente el "objeto" no deben llamar "base" en "GetHashCode" o "Equals"

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

```cs MyDelegate first, second, third, fourth;
first = () => Console.Write("1");
second = () => Console.Write("2");
third = () => Console.Write("3");
fourth = () => Console.Write("4");

MyDelegate chain1234 = first + second + third + fourth; // Compliant - chain sequence = "1234"
MyDelegate chain12 = chain1234 - third - fourth; // Compliant - chain sequence = "12"


MyDelegate chain14 = first + fourth; // creates a new MyDelegate instance which is a list under the covers
MyDelegate chain23 = chain1234 - chain14; // Noncompliant; (first + fourth) doesn't exist in chain1234


// The chain sequence of "chain23" will be "1234" instead of "23"!
// Indeed, the sequence "1234" does not contain the subsequence "14", so nothing is subtracted
// (but note that "1234" contains both the "1" and "4" subsequences)
chain23 = chain1234 - (first + fourth); // Noncompliant

chain23(); // will print "1234"!
```

```cs MyDelegate chain23 = chain1234 - first - fourth; // Compliant - "1" is first removed, followed by "4"

chain23(); // will print "23"
```





# Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

```cs class HttpPrinter
{
  private string content;

  public async void CallNetwork(string url) //Noncompliant
  {
    var client = new HttpClient();
    var response = await client.GetAsync(url);
    content = await response.Content.ReadAsStringAsync();
  }

  public async Task PrintContent(string url)  // works correctly if web request finishes in under 1 second, otherwise content will be null
  {
    CallNetwork(url);
    await Task.Delay(1000);
    Console.Write(content);
  }
}
```

```cs class HttpPrinter
{
  private string content;

  public async Task CallNetwork(string url)
  {
    var client = new HttpClient();
    var response = await client.GetAsync(url);
    content = await response.Content.ReadAsStringAsync();
  }

  public async Task PrintContent(string url)
  {
    await CallNetwork(url); // <----- call changed here. If await is not added warning CS4014 will be triggered
    await Task.Delay(1000);
    Console.Write(content);
  }
}
```

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.





# Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

```cs public class MyClass
{
  [ThreadStatic]  // Noncompliant
  private int count = 0;

  // ...
}
```

```cs public class MyClass
{
  private int count = 0;

  // ...
}
```

Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

```cs public class MyClass
{
  private readonly ThreadLocal<int> count = new ThreadLocal<int>();
  public int Count
  {
    get { return count.Value; }
    set { count.Value = value; }
  }
  // ...
}
```





# Restar una cadena de delegados de otra podría producir resultados inesperados como se muestra a continuación, y es probable que sea un error.

Por lo general, desea utilizar el uso para crear una variable IDisponible local;

```cs public FileStream WriteToFile(string path, string text)
{
  using (var fs = File.Create(path)) // Noncompliant
  {
    var bytes = Encoding.UTF8.GetBytes(text);
    fs.Write(bytes, 0, bytes.Length);
    return fs;
  }
}
```

```cs public FileStream WriteToFile(string path, string text)
{
  var fs = File.Create(path);
  var bytes = Encoding.UTF8.GetBytes(text);
  fs.Write(bytes, 0, bytes.Length);
  return fs;
}
```





# Por lo general, desea utilizar el uso para crear una variable IDisponible local;

Por lo general, desea utilizar el uso para crear una variable IDisponible local;

Por lo general, desea utilizar el uso para crear una variable IDisponible local;

```cs public class Foo
{
  [ThreadStatic]
  public static object PerThreadObject = new object(); // Noncompliant. Will be null in all the threads except the first one.
}
```

```cs public class Foo
{
  [ThreadStatic]
  public static object _perThreadObject;
  public static object PerThreadObject
  {
    get
    {
      if (_perThreadObject == null)
      {
        _perThreadObject = new object();
      }
      return _perThreadObject;
    }
  }
}
```





# Por lo general, desea utilizar el uso para crear una variable IDisponible local;

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

```cs public class MyClass
{
  private MyStruct myStruct;

  public void DoSomething(MyStruct s1) {
    int a = 1;
    int b = 1;

    if (Object.ReferenceEquals(myStruct, s1))  // Noncompliant; this can never be true
    {
      // ...
    }
    else if (Object.ReferenceEquals(a,b)) // Noncompliant
    {
      // ...
    }
  }
}
```





# El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

```cs int v1 = 0;
bool v2 = false;

var v3 = !!v1; // Noncompliant
var v4 = ~~v2; // Noncompliant
```

```cs int v1 = 0;
bool v2 = false;

var v3 = !v1;
var v4 = ~v2;
```





# El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

```cs public bool CanVote(Person person)
{
  return person.GetAge() > 18 ? true : true; // Noncompliant; is this what was intended?
}
```

```cs public bool CanVote(Person person)
{
  return person.GetAge() > 18 ? true : false;
  // or even better:
  // return person.GetAge() > 18;
}
```

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.





# El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

```cs int target = -5;
int num = 3;

target =- num;  // Noncompliant; target = -3. Is that really what's meant?
target =+ num; // Noncompliant; target = 3
```

```cs int target = -5;
int num = 3;

target = -num;  // Compliant; intent to assign inverse value of num is clear
target += num;
```





# El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

```cs var a = double.NaN;

if (a == double.NaN) // Noncompliant; always false
{
  Console.WriteLine("a is not a number");  // this is dead code
}
if (a != double.NaN)  // Noncompliant; always true
{
  Console.WriteLine("a is not NaN"); // this statement is not necessarily true
}
```

```cs if (double.IsNaN(a))
{
  console.log("a is not a number");
}
```





# El uso de Object.ReferenceEquals para comparar las referencias de dos tipos de valores simplemente no devolverá los resultados esperados la mayor parte del tiempo porque dichos tipos se pasan por valor, no por referencia.

Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

```cs a = false;
if (a) // Noncompliant
{
  DoSomething(); // never executed
}

if (!a || b) // Noncompliant; "!a" is always "true", "b" is never evaluated
{
  DoSomething();
}
else
{
  DoSomethingElse(); // never executed
}
```

Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

```cs const bool debug = false;
//...
if (debug)
{
  // Print something
}
```

Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.





# Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

```cs object o = null;
if (condition)
{
  M1(o.ToString()); // Noncompliant, always null
}
else
{
  o = new object();
}
M2(o.ToString());
```

Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

```cs using System;

public sealed class ValidatedNotNullAttribute : Attribute { }

public static class Guard
{
    public static void NotNull<T>([ValidatedNotNull] this T value, string name) where T : class
    {
        if (value == null)
            throw new ArgumentNullException(name);
    }
}

public static class Utils
{
    public static string ToUpper(string value)
    {
        Guard.NotNull(value, nameof(value));
        if (value == null)
        {
            return value.ToString(); // Compliant, this code is not reachable
        }
        return value.ToUpper();
    }
}
```





# Las expresiones condicionales que son siempre verdaderas o falsas pueden llevar a código muerto.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs public override string ToString ()
{
  if (this.collection.Count == 0)
  {
    return null; // Noncompliant
  }
  else
  {
    // ...
  }
}
```

```cs public override string ToString ()
{
  if (this.collection.Count == 0)
  {
    return string.Empty;
  }
  else
  {
    // ...
  }
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs coll.Where(i => i > 5).Select(i => i*i); // Noncompliant
"this string".Equals("other string"); // Noncompliant
```

```cs var res = coll.Where(i => i > 5).Select(i => i*i);
var isEqual = "this string".Equals("other string");
```

Llamar a ToString () en un objeto siempre debe devolver una cadena.





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs public int PickNumber()
{
  int i = 0;
  int j = 0;

  i = i++; // Noncompliant; i is still zero

  return j++; // Noncompliant; 0 returned
}
```

```cs public int PickNumber()
{
  int i = 0;
  int j = 0;

  i++;
  return ++j;
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs var list = new List<int>();

list.AddRange(list); // Noncompliant
list.Concat(list); // Noncompliant

list.Union(list); // Noncompliant; always returns list
list.Except(list); // Noncompliant; always empty
list.Intersect(list); // Noncompliant; always list
list.SequenceEqual(list); // Noncompliant; always true

var set = new HashSet<int>();
set.UnionWith(set); // Noncompliant; no changes
set.ExceptWith(set); // Noncompliant; always empty
set.IntersectWith(set); // Noncompliant; no changes
set.IsProperSubsetOf(set); // Noncompliant; always false
set.IsProperSupersetOf(set); // Noncompliant; always false
set.IsSubsetOf(set); // Noncompliant; always true
set.IsSupersetOf(set); // Noncompliant; always true
set.Overlaps(set); // Noncompliant; always true
set.SetEquals(set); // Noncompliant; always true
set.SymmetricExceptWith(set); // Noncompliant; always empty
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs if (param == 1)
{
  OpenWindow();
}
else if (param == 2)
{
  CloseWindow();
}
else if (param == 1) // Noncompliant
{
  MoveWindowToTheBackground();
}
```

```cs if (param == 1)
{
  OpenWindow();
}
else if (param == 2)
{
  CloseWindow();
}
else if (param == 3)
{
  MoveWindowToTheBackground();
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs if (x < 0)
  new ArgumentException("x must be nonnegative");
```

```cs if (x < 0)
  throw new ArgumentException("x must be nonnegative");
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs if ( a == a ) // always true
{
  doZ();
}
if ( a != a ) // always false
{
  doY();
}
if ( a == b && a == b ) // if the first one is true, the second one is too
{
  doX();
}
if ( a == b || a == b ) // if the first one is true, the second one is too
{
  doW();
}

int j = 5 / 5; //always 1
int k = 5 - 5; // always 0

c.Equals(c);    //always true
Object.Equals(c, c); //always true
```

Llamar a ToString () en un objeto siempre debe devolver una cadena.





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs for (int i = 0; i < 10; i++)
{
    Console.WriteLine(i);
    break;  // Noncompliant, loop only executes once
}
...
foreach (var item in items)
{
    return item;  // Noncompliant, loop only executes once
}
...
```

```cs for (int i = 0; i < 10; i++)
{
    Console.WriteLine(i);
}
...
var item = items.FirstOrDefault();
if (item != null)
{
    return item;
}
...
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs public void SetName(string name)
{
  name = name;
}
```

```cs public void SetName(string name)
{
  this.name = name;
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs var ip = "192.168.12.42";
var address = IPAddress.Parse(ip);
```

```cs var ip = ConfigurationManager.AppSettings["myapplication.ip"];
var address = IPAddress.Parse(ip);
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs public void Foo()
{
    var g = new Guid(); // Noncompliant - what's the intent?
}
```

```cs public void Foo(byte[] bytes)
{
    var g1 = Guid.Empty;
    var g2 = Guid.NewGuid();
    var g3 = new Guid(bytes);
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs public static async Task SkipLinesAsync(this TextReader reader, int linesToSkip) // Noncompliant
{
    if (reader == null) { throw new ArgumentNullException(nameof(reader)); }
    if (linesToSkip < 0) { throw new ArgumentOutOfRangeException(nameof(linesToSkip)); }

    for (var i = 0; i < linesToSkip; ++i)
    {
        var line = await reader.ReadLineAsync().ConfigureAwait(false);
        if (line == null) { break; }
    }
}
```

```cs public static Task SkipLinesAsync(this TextReader reader, int linesToSkip)
{
    if (reader == null) { throw new ArgumentNullException(nameof(reader)); }
    if (linesToSkip < 0) { throw new ArgumentOutOfRangeException(nameof(linesToSkip)); }

    return reader.SkipLinesInternalAsync(linesToSkip);
}

private static async Task SkipLinesInternalAsync(this TextReader reader, int linesToSkip)
{
    for (var i = 0; i < linesToSkip; ++i)
    {
        var line = await reader.ReadLineAsync().ConfigureAwait(false);
        if (line == null) { break; }
    }
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs public static IEnumerable<TSource> TakeWhile<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate) // Noncompliant
{
    if (source == null) { throw new ArgumentNullException(nameof(source)); }
    if (predicate == null) { throw new ArgumentNullException(nameof(predicate)); }

    foreach (var element in source)
    {
        if (!predicate(element)) { break; }
        yield return element;
    }
}
```

```cs public static IEnumerable<TSource> TakeWhile<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate)
{
    if (source == null) { throw new ArgumentNullException(nameof(source)); }
    if (predicate == null) { throw new ArgumentNullException(nameof(predicate)); }
    return TakeWhileIterator<TSource>(source, predicate);
}

private static IEnumerable<TSource> TakeWhileIterator<TSource>(IEnumerable<TSource> source, Func<TSource, bool> predicate)
{
    foreach (TSource element in source)
    {
        if (!predicate(element)) break;
        yield return element;
    }
}
```





# Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

Llamar a ToString () en un objeto siempre debe devolver una cadena.

```cs using System;

namespace MyLibrary
{
  class Foo
  {
    public event EventHandler ThresholdReached;

    protected virtual void OnThresholdReached(EventArgs e)
    {
        ThresholdReached?.Invoke(null, e); // Noncompliant
    }
  }
}
```

```cs using System;

namespace MyLibrary
{
  class Foo
  {
    public event EventHandler ThresholdReached;

    protected virtual void OnThresholdReached(EventArgs e)
    {
        ThresholdReached?.Invoke(this, e);
    }
  }
}
```





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs using System;
using System.Runtime.InteropServices;

namespace MyLibrary
{
    public class Foo
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern bool RemoveDirectory(string name);  // Noncompliant
    }
}
```

```cs using System;
using System.Runtime.InteropServices;

namespace MyLibrary
{
    public class Foo
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern bool RemoveDirectory(string name);
    }
}
```





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs using System;
using System.Runtime.InteropServices;

namespace MyLibrary
{
  class Foo
  {
    [DllImport("mynativelib")]
    extern public static void Bar(string s, int x); // Noncompliant
  }
}
```

```cs using System;
using System.Runtime.InteropServices;

namespace MyLibrary
{
  class Foo
  {
    [DllImport("mynativelib")]
    extern private static void Bar(string s, int x);

    public void BarWrapper(string s, int x)
    {
      if (s != null && x >= 0  && x < s.Length)
      {
        bar(s, x);
      }
    }
  }
}
```





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs private const string CODE = "bounteous";
private int callCount = 0;

public string GetCode()
{
  callCount++;
  return CODE;
}

public string GetName()  // Noncompliant
{
  callCount++;
  return CODE;
}
```

```cs private const string CODE = "bounteous";
private int callCount = 0;

public string GetCode()
{
  callCount++;
  return CODE;
}

public string GetName()
{
  return GetCode();
}
```

Los métodos "P / Invoke" no deberían ser visibles





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs using System;

namespace MyLibrary
{
    [FlagsAttribute]
    public enum Color // Noncompliant, Orange is neither a power of two, nor a combination of any of the defined values
    {
        None    = 0,
        Red     = 1,
        Orange  = 3,
        Yellow  = 4
    }
}
```

```cs using System;

namespace MyLibrary
{
    public enum Color // Compliant - no FlagsAttribute attribute
    {
        None = 0,
        Red = 1,
        Orange = 3,
        Yellow = 4
    }

    [FlagsAttribute]
    public enum Days
    {
        None = 0,
        Monday = 1,
        Tuesday = 2,
        Wednesday = 4,
        Thursday = 8,
        Friday = 16,
        All = Monday| Tuesday | Wednesday | Thursday | Friday    // Compliant - combination of other values
    }
}
```





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs using System;

namespace MyLibrary
{
  class Base : IEquatable<Base> // Noncompliant
  {
    bool Equals(Base other)
    {
      if (other == null) { return false };
      // do comparison of base properties
    }

    override bool Equals(object other)  => Equals(other as Base);
  }

  class A : Base
  {
    bool Equals(A other)
    {
      if (other == null) { return false };
      // do comparison of A properties
      return base.Equals(other);
    }

    override bool Equals(object other)  => Equals(other as A);
  }

  class B : Base
  {
    bool Equals(B other)
    {
      if (other == null) { return false };
      // do comparison of B properties
     return base.Equals(other);
    }

    override bool Equals(object other)  => Equals(other as B);
  }

  static void Main() {
    A a = new A();
    B b = new B();

    Console.WriteLine(a.Equals(b)); // This calls the WRONG equals. This causes Base::Equals(Base)
    //  to be called which only compares the properties in Base and ignores the fact that
    // a and b are different types. In the working example A::Equals(Object) would have been
    // called and Equals would return false because it correctly recognizes that a and b are
    // different types. If a and b have the same base properties they will  be returned as equal.
  }
}
```

```cs using System;

namespace MyLibrary
{
    public sealed class Foo : IEquatable<Foo>
    {
        public bool Equals(Foo other)
        {
            // Your code here
        }
    }
}
```

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs using System;

namespace MyLibrary
{
  public enum Color
  {
        None,
        Red,
        Orange,
        Yellow,
        ReservedColor  // Noncompliant
    }
}
```





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs public void Foo(Bar a, int[] b)
{
  throw new ArgumentException(); // Noncompliant
  throw new ArgumentException("My error message", "c"); // Noncompliant
  throw new ArgumentException("My error message", "c", innerException); // Noncompliant
  throw new ArgumentNullException("c"); // Noncompliant
  throw new ArgumentNullException("My error message",?"c"); // Noncompliant
  throw new ArgumentOutOfRangeException("c");
  throw new ArgumentOutOfRangeException("c", "My error message"); // Noncompliant
  throw new ArgumentOutOfRangeException("c",?b,?"My error message"); // Noncompliant
}
```

```cs public void Foo(Bar a, Bar b)
{
  throw new ArgumentException("My error message", "a");
  throw new ArgumentException("My error message", "b", innerException);
  throw new ArgumentNullException("a");
  throw new ArgumentNullException(nameOf(a));
  throw new ArgumentNullException("My error message",?"a");
  throw new ArgumentOutOfRangeException("b");
  throw new ArgumentOutOfRangeException("b", "My error message");
  throw new ArgumentOutOfRangeException("b",?b,?"My error message");
}
```

Los métodos "P / Invoke" no deberían ser visibles





# Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

Los métodos "P / Invoke" no deberían ser visibles

```cs public class Foo : ISerializable // Noncompliant the [Serializable] attribute is missing
{
}
```

Los métodos "P / Invoke" no deberían ser visibles

```cs public class Bar
{
}

[Serializable]
public class Foo : ISerializable // Noncompliant the serialization constructor is missing
{
    private readonly Bar bar; // Noncompliant the field is not marked with [NonSerialized]
}
```

```cs public class Bar
{
}

[Serializable]
public class Foo : ISerializable
{
    [NonSerialized]
    private readonly Bar bar;

    public Foo()
    {
        // ...
    }

    protected Foo(SerializationInfo info, StreamingContext context)
    {
        // ...
    }

    public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        // ...
    }
}

[Serializable]
public sealed class SubFoo : Foo
{
    private int val;

    public SubFoo()
    {
        // ...
    }

    private SubFoo(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
        // ...
    }

    public override void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        base.GetObjectData(info, context);
        // ...
    }
}
```





# Se debe utilizar "Assembly.Load"

Se debe utilizar "Assembly.Load"

Se debe utilizar "Assembly.Load"

```cs static void Main(string[] args)
{
    Assembly.LoadFrom(...); // Noncompliant
    Assembly.LoadFile(...); // Noncompliant
    Assembly.LoadWithPartialName(...); // Noncompliant + deprecated
}
```





# Se debe utilizar "Assembly.Load"

Se debe utilizar "Assembly.Load"

Se debe utilizar "Assembly.Load"

Se debe utilizar "Assembly.Load"

```cs public class Foo1 : IDisposable // Noncompliant - provide protected overridable implementation of Dispose(bool) on Foo or mark the type as sealed.
{
    public void Dispose() // Noncompliant - should contain only a call to Dispose(true) and then GC.SuppressFinalize(this)
    {
        // Cleanup
    }
}

public class Foo2 : IDisposable
{
    void IDisposable.Dispose() // Noncompliant - Dispose() should be public
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public virtual void Dispose() // Noncompliant - Dispose() should be sealed
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}

public class Foo3 : IDisposable
{
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        // Cleanup
    }

    ~Foo3() // Noncompliant - Modify Foo.~Foo() so that it calls Dispose(false) and then returns.
    {
        // Cleanup
    }
}{code}
```

```cs // Sealed class
public sealed class Foo1 : IDisposable
{
    public void Dispose()
    {
        // Cleanup
    }
}

// Simple implementation
public class Foo2 : IDisposable
{
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        // Cleanup
    }
}

// Implementation with a finalizer
public class Foo3 : IDisposable
{
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        // Cleanup
    }

    ~Foo3()
    {
        Dispose(false);
    }
}

// Base disposable class
public class Foo4 : DisposableBase
{
    protected override void Dispose(bool disposing)
    {
        // Cleanup
        // Do not forget to call base
        base.Dispose(disposing);
    }
}
```

Se debe utilizar "Assembly.Load"





# Se debe utilizar "Assembly.Load"

El atributo ServiceContract especifica que una clase o interfaz define el contrato de comunicación de un servicio de Windows Communication Foundation (WCF).

```cs [ServiceContract]
interface IMyService // Noncompliant
{
  int MyServiceMethod();
}
```

```cs [ServiceContract]
interface IMyService
{
  [OperationContract]
  int MyServiceMethod();
}
```





# El atributo ServiceContract especifica que una clase o interfaz define el contrato de comunicación de un servicio de Windows Communication Foundation (WCF).

Debido a que las cadenas de formato compuesto se interpretan en tiempo de ejecución, en lugar de ser validadas por el compilador, pueden contener errores que conducen a comportamientos inesperados o errores de tiempo de ejecución.

```cs s = string.Format("{0}", arg0, arg1); // Noncompliant, arg1 is declared but not used.
s = string.Format("{0} {2}", arg0, arg1, arg2); // Noncompliant, the format item with index 1 is missing so arg1 will not be used.
s = string.Format("foo"); // Noncompliant, there is no need to use string.Format here.
```

```cs s = string.Format("{0}", arg0);
s = string.Format("{0} {1}", arg0, arg2);
s = "foo";
```

```cs var pattern = "{0} {1} {2}";
var res = string.Format(pattern, 1, 2); // Compliant, not const string are not recognized
```

```cs var array = new int[] {};
var res = string.Format("{0} {1}", array); // Compliant we don't know the size of the array
```





# Debido a que las cadenas de formato compuesto se interpretan en tiempo de ejecución, en lugar de ser validadas por el compilador, pueden contener errores que conducen a comportamientos inesperados o errores de tiempo de ejecución.

Debido a que las cadenas de formato compuesto se interpretan en tiempo de ejecución, en lugar de ser validadas por el compilador, pueden contener errores que conducen a comportamientos inesperados o errores de tiempo de ejecución.

```cs try
{}
catch(ExceptionType1 exc)
{
  Console.WriteLine(exc);
  throw exc; // Noncompliant; stacktrace is reset
}
catch (ExceptionType2 exc)
{
  throw new Exception("My custom message", exc);  // Compliant; stack trace preserved
}
```

```cs try
{}
catch(ExceptionType1 exc)
{
  Console.WriteLine(exc);
  throw;
}
catch (ExceptionType2 exc)
{
  throw new Exception("My custom message", exc);
}
```





# Debido a que las cadenas de formato compuesto se interpretan en tiempo de ejecución, en lugar de ser validadas por el compilador, pueden contener errores que conducen a comportamientos inesperados o errores de tiempo de ejecución.

Ya que las clases abstractas no pueden ser instanciadas, no tiene sentido que tengan constructores públicos o internos.

```cs abstract class Base
{
    public Base() // Noncompliant, should be private or protected
    {
      //...
    }
}
```

```cs abstract class Base
{
    protected Base()
    {
      //...
    }
}
```





# Ya que las clases abstractas no pueden ser instanciadas, no tiene sentido que tengan constructores públicos o internos.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs Assert.AreEqual(runner.ExitCode, 0, "Unexpected exit code");  // Noncompliant; Yields error message like: Expected:<-1>. Actual:<0>.
```

```cs Assert.AreEqual(0, runner.ExitCode, "Unexpected exit code");
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public string GetTitle(Person p)
{
  return p.Gender == Gender.MALE ? "Mr. " : p.IsMarried ? "Mrs. " : "Miss ";  // Noncompliant
}
```

```cs public string GetTitle(Person p)
{
  if (p.Gender == Gender.MALE)
  {
    return "Mr. ";
  }
  return p.IsMarried ? "Mrs. " : "Miss ";
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs class UninvokedEventSample
{
    private event Action<object, EventArgs> Happened; //Noncompliant

    public void RegisterEventHandler(Action<object, EventArgs> handler)
    {
        Happened += handler; //we register some event handlers
    }

    public void RaiseEvent()
    {
        if (Happened != null)
        {
            // Happened(this, null); // the event is never triggered, because this line is commented out.
        }
    }
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs class Base
{
  public virtual void Method(params int[] numbers)
  {
    ...
  }
}
class Derived : Base
{
  public override void Method(int[] numbers) // Noncompliant, the params is missing.
  {
    ...
  }
}
```

```cs class Base
{
  public virtual void Method(params int[] numbers)
  {
    ...
  }
}
class Derived : Base
{
  public override void Method(params int[] numbers)
  {
    ...
  }
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs interface IConsumer<T>  // Noncompliant
{
    bool Eat(T fruit);
}
```

```cs interface IConsumer<in T>
{
    bool Eat(T fruit);
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs var x = personList
  .OrderBy(person => person.Age)
  .OrderBy(person => person.Name)  // Noncompliant
  .ToList();  // x is sorted by Name, not sub-sorted
```

```cs var x = personList
  .OrderBy(person => person.Age)
  .ThenBy(person => person.Name)
  .ToList();
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public class Person
{
  private static DateTime dateOfBirth;
  private static int expectedFingers;

  public Person(DateTime birthday)
  {
    dateOfBirth = birthday;  // Noncompliant; now everyone has this birthday
    expectedFingers = 10;  // Noncompliant
  }
}
```

```cs public class Person
{
  private DateTime dateOfBirth;
  private static int expectedFingers = 10;

  public Person(DateTime birthday)
  {
    this.dateOfBirth = birthday;
  }
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs seq1.Select(element => element as T).Any(element => element != null);  // Noncompliant; use OfType
seq2.Select(element => element as T).Any(element => element != null && CheckCondition(element));  // Noncompliant; use OfType
seq3.Where(element => element is T).Select(element => element as T); // Noncompliant; use OfType
seq4.Where(element => element is T).Select(element => (T)element); // Noncompliant; use OfType
seq5.Where(element => [expression]).Any();  // Noncompliant; use Any([expression])

var num = seq6.Count(); // Noncompliant
var arr = seq.ToList().ToArray(); //Noncompliant
var count = seq.ToList().Count(x=>[condition]); //Noncompliant
```

```cs seq1.OfType<T>().Any();
seq2.OfType<T>().Any(element => CheckCondition(element));
seq3.OfType<T>();
seq4.OfType<T>();
seq5.Any(element => [expression])

var num = seq6.Count;
var arr = seq.ToArray();
var count = seq.Count(x=>[condition]);
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs class Person
{
  int _birthYear;  // Noncompliant
  Person(int birthYear)
  {
    _birthYear = birthYear;
  }
}
```

```cs class Person
{
  readonly int _birthYear;
  Person(int birthYear)
  {
    _birthYear = birthYear;
  }
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public class LengthLimitedSingletonCollection<T> where T : new()
{
  protected const int MaxAllowedLength = 5;
  protected static Dictionary<Type, object> instances = new Dictionary<Type, object>(); // Noncompliant

  public static T GetInstance()
  {
    object instance;

    if (!instances.TryGetValue(typeof(T), out instance))
    {
      if (instances.Count >= MaxAllowedLength)
      {
        throw new Exception();
      }
      instance = new T();
      instances.Add(typeof(T), instance);
    }
    return (T)instance;
  }
}
```

```cs public class SingletonCollectionBase
{
  protected static Dictionary<Type, object> instances = new Dictionary<Type, object>();
}

public class LengthLimitedSingletonCollection<T> : SingletonCollectionBase where T : new()
{
  protected const int MaxAllowedLength = 5;

  public static T GetInstance()
  {
    object instance;

    if (!instances.TryGetValue(typeof(T), out instance))
    {
      if (instances.Count >= MaxAllowedLength)
      {
        throw new Exception();
      }
      instance = new T();
      instances.Add(typeof(T), instance);
    }
    return (T)instance;
  }
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public class Cache<T>
{
   private static Dictionary<string, T> CacheDictionary { get; set; } // Compliant
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs if (condition)
  FirstActionInBlock();
  SecondAction();  // Noncompliant; executed unconditionally
ThirdAction();

if(condition) FirstActionInBlock(); SecondAction();  // Noncompliant; secondAction executed unconditionally

if(condition) FirstActionInBlock();  // Noncompliant
  SecondAction();  // Executed unconditionally

string str = null;
for (int i = 0; i < array.Length; i++)
  str = array[i];
  DoTheThing(str);  // Noncompliant; executed only on last array element
```

```cs if (condition)
{
  FirstActionInBlock();
  SecondAction();
}
ThirdAction();

string str = null;
for (int i = 0; i < array.Length; i++)
{
  str = array[i];
  DoTheThing(str);
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs a = true;
if (a) // Noncompliant
{
  DoSomething();
}

if (b && a) // Noncompliant; "a" is always "true"
{
  DoSomething();
}

if (c || !a) // Noncompliant; "!a" is always "false"
{
  DoSomething();
}
```

```cs a = true;
if (Foo(a))
{
  DoSomething();
}

if (b)
{
  DoSomething();
}

if (c)
{
  DoSomething();
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs <S, T, U, V> void foo() {} // Noncompliant; not really readable
<String, Integer, Object, String>foo(); // especially on invocations
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs class Program
{
    public int Foo  //Non-Compliant
    {
        set
        {
            // ... some code ...
        }
    }
}
```

```cs class Program
{
    private int foo;

    public void SetFoo(int value)
    {
        // ... some code ...
        foo = value;
    }
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs class Program
{
  public int Foo { get; set; } // Compliant
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public int Foo
{
    get
    {
        throw new Exception(); // Noncompliant
    }
}
```

```cs public int Foo
{
    get
    {
        return 42;
    }
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs try
{
  DoTheFirstThing(a, b);
}
catch (InvalidOperationException ex)
{
  HandleException(ex);
}

DoSomeOtherStuff();

try  // Noncompliant; catch is identical to previous
{
  DoTheSecondThing();
}
catch (InvalidOperationException ex)
{
  HandleException(ex);
}

try  // Compliant; catch handles exception differently
{
  DoTheThirdThing(a);
}
catch (InvalidOperationException ex)
{
  LogAndDie(ex);
}
```

```cs try
{
  DoTheFirstThing(a, b);
  DoSomeOtherStuff();
  DoTheSecondThing();
}
catch (InvalidOperationException ex)
{
  HandleException(ex);
}

try  // Compliant; catch handles exception differently
{
  DoTheThirdThing(a);
}
catch (InvalidOperationException ex)
{
  LogAndDie(ex);
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public class MoreMath<T>   // Noncompliant; <T> is ignored
{
  public int Add<T>(int a, int b) // Noncompliant; <T> is ignored
  {
    return a + b;
  }
}
```

```cs public class MoreMath
{
  public int Add (int a, int b)
  {
    return a + b;
  }
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs public double Divide(int divisor, int dividend)
{
  return divisor/dividend;
}

public void DoTheThing()
{
  int divisor = 15;
  int dividend = 5;

  double result = Divide(dividend, divisor);  // Noncompliant; operation succeeds, but result is unexpected
  //...
}
```

```cs public double Divide(int divisor, int dividend)
{
  return divisor/dividend;
}

public void DoTheThing()
{
  int divisor = 15;
  int dividend = 5;

  double result = Divide(divisor, dividend);
  //...
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs switch (i)
{
  case 1:
    DoFirst();
    DoSomething();
    break;
  case 2:
    DoSomethingDifferent();
    break;
  case 3:  // Noncompliant; duplicates case 1's implementation
    DoFirst();
    DoSomething();
    break;
  default:
    DoTheRest();
}

if (a >= 0 && a < 10)
{
  DoFirst();
  DoTheThing();
}
else if (a >= 10 && a < 20)
{
  DoTheOtherThing();
}
else if (a >= 20 && a < 50)   // Noncompliant; duplicates first condition
{
  DoFirst();
  DoTheThing();
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs if (a >= 0 && a < 10)
{
  DoTheThing();
}
else if (a >= 10 && a < 20)
{
  DoTheOtherThing();
}
else if (a >= 20 && a < 50)    //no issue, usually this is done on purpose to increase the readability
{
  DoTheThing();
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs if(a == 1)
{
  doSomething();  //Noncompliant, this might have been done on purpose but probably not
}
else if (a == 2)
{
  doSomething();
}
```





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs i = a + b; // Noncompliant; calculation result not used before value is overwritten
i = compute();
```

```cs i = a + b;
i += compute();
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs [TestMethod]
[Ignore]  // Noncompliant
public void Test_DoTheThing()
{
  // ...
}
```

```cs [TestMethod]
[Ignore]  // renable when TCKT-1234 is fixed
public void Test_DoTheThing()
{
  // ...
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs [TestMethod]
[Ignore]
[WorkItem(1234)]
public void Test_DoTheThing()
{
  // ...
}
```

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.





# Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

Los métodos estándar de la biblioteca de aserciones, como AreEqual y AreSame en MSTest y NUnit, o Equal and Same en XUnit, esperan que el primer argumento sea el valor esperado y el segundo argumento sea el valor real.

```cs void DoSomething(int a, int b) // "b" is unused
{
  Compute(a);
}

void DoSomething2(int a) // value of "a" is unused
{
  a = 10;
  Compute(a);
}
```

```cs void DoSomething(int a)
{
  Compute(a);
}

void DoSomething2()
{
  var a = 10;
  Compute(a);
}
```

Se ignoran los métodos virtuales, los métodos de anulación y las implementaciones de interfaz.

```cs override void DoSomething(int a, int b) // no issue reported on b
{
  Compute(a);
}
```

Además, este parámetro de los métodos de extensión también se ignora.

```cs public static class Extensions
{
  public static void MyHelper(this HtmlHelper helper) //no issue reported here
  {
    // no use of helper here
  }
}
```

Los métodos que tienen atributos definidos en ellos se ignoran.

```cs public class MyDto
{
  public string Name { get; set; }

  [OnDeserialized]
  private void OnDeserialized(StreamingContext context)
  {
    // ...
  }
}
```

Los métodos vacíos o no compatibles se ignoran.

```cs public void DoSomething()
{}

public void Call()
{
  throw new NotImplementedException();
}
```

Y, obviamente, no se plantea ningún problema en el método estático vacío (cadena [] args)





# Las matrices vacías y las colecciones deben devolverse en lugar de ser nulas.

Devolver nulo en lugar de una matriz o colección real obliga a los llamadores del método a probar explícitamente la nulidad, haciéndolos más complejos y menos legibles.

Devolver nulo en lugar de una matriz o colección real obliga a los llamadores del método a probar explícitamente la nulidad, haciéndolos más complejos y menos legibles.

```cs public Result[] GetResults()
{
    return null; // Noncompliant
}

public IEnumerable<Result> GetResults()
{
    return null; // Noncompliant
}

public IEnumerable<Result> GetResults() => null; // Noncompliant

public IEnumerable<Result> Results
{
    get
    {
        return null; // Noncompliant
    }
}

public IEnumerable<Result> Results => null; // Noncompliant
```

```cs public Result[] GetResults()
{
    return new Result[0];
}

public IEnumerable<Result> GetResults()
{
    return Enumerable.Empty<Result>();
}

public IEnumerable<Result> GetResults() => Enumerable.Empty<Result>();

public IEnumerable<Result> Results
{
    get
    {
        return Enumerable.Empty<Result>();
    }
}

public IEnumerable<Result> Results => Enumerable.Empty<Result>();
```

Aunque la cadena es una colección, la regla no informa sobre ella.





# Los tipos o miembros privados no utilizados deben ser eliminados

Los tipos o miembros privados no utilizados deben ser eliminados

```cs public class Foo
{
  private void UnusedPrivateMethod() {...} // Noncompliant

  private class UnusedClass {...} // Noncompliant
}
```

```cs public class Foo
{
  public Foo()
  {
    UsedPrivateMethod();
  }

  private void UsedPrivateMethod()
  {
    var c = new UsedClass();
  }

  private class UsedClass {...}
}
```

Esta regla no plantea problemas en:





# Seguimiento de los usos de las etiquetas "FIXME"

Las etiquetas FIXME se usan comúnmente para marcar los lugares donde se sospecha un error, pero que el desarrollador desea tratar más adelante.

A veces, el desarrollador no tendrá tiempo o simplemente se olvidará de volver a esa etiqueta.

A veces, el desarrollador no tendrá tiempo o simplemente se olvidará de volver a esa etiqueta.

```cs private int Divide(int numerator, int denominator)
{
  return numerator / denominator;              // FIXME denominator value might be  0
}
```





# Los atributos "obsoletos" deben incluir explicaciones

El atributo Obsoleto se puede aplicar con o sin argumentos, pero marcar algo Obsoleto sin incluir consejos sobre por qué es obsoleto o qué usar, en cambio, los mantenedores perderán tiempo tratando de resolverlos, cada vez que se encuentre la advertencia.

```cs public class Car
{

  [Obsolete]  // Noncompliant
  public void CrankEngine(int turnsOfCrank)
  { ... }
}
```

```cs public class Car
{

  [Obsolete("Replaced by the automatic starter")]
  public void CrankEngine(int turnsOfCrank)
  { ... }
}
```





# Las asignaciones no deben hacerse dentro de las sub-expresiones

Las asignaciones dentro de las sub-expresiones son difíciles de detectar y, por lo tanto, hacen que el código sea menos legible.

```cs if (string.IsNullOrEmpty(result = str.Substring(index, length))) // Noncompliant
{
  //...
}
```

```cs var result = str.Substring(index, length);
if (string.IsNullOrEmpty(result))
{
  //...
}
```

Se permiten las asignaciones dentro de lambda y las expresiones delegadas.

Además, también se aceptan los siguientes patrones:

```cs var a = b = c = 10;
```

```cs while ((val = GetNewValue()) > 0)
{
...
}
```

```cs private MyClass instance;
public MyClass Instance
{
  get
  {
    return instance ?? (instance = new MyClass());
  }
}
```





# Las excepciones generales nunca deben ser lanzadas.

Lanzar excepciones generales como Exception, SystemException, ApplicationException, IndexOutOfRangeException, NullReferenceException, OutOfMemoryException y ExecutionEngineException evita que los métodos de llamada manejen las excepciones verdaderas generadas por el sistema de manera diferente a los errores generados por la aplicación.

```cs public void DoSomething(object obj)
{
  if (obj == null)
  {
    throw new NullReferenceException("obj");  // Noncompliant
  }
  // ...
}
```

```cs public void DoSomething(object obj)
{
  if (obj == null)
  {
    throw new ArgumentNullException("obj");
  }
  // ...
}
```





# Las clases de utilidad no deben tener constructores públicos.

Las clases de utilidad, que son colecciones de miembros estáticos, no deben crearse instancias.

C # agrega un constructor público implícito a cada clase que no define explícitamente al menos un constructor.

```cs public class StringUtils // Noncompliant
{
  public static string Concatenate(string s1, string s2)
  {
    return s1 + s2;
  }
}
```

```cs public static class StringUtils
{
  public static string Concatenate(string s1, string s2)
  {
    return s1 + s2;
  }
}
```

C # agrega un constructor público implícito a cada clase que no define explícitamente al menos un constructor.

```cs public class StringUtils
{
  protected StringUtils()
  {
  }
  public static string Concatenate(string s1, string s2)
  {
    return s1 + s2;
  }
}
```





# Las variables locales no deben sombrear los campos de clase

Sombrear campos con una variable local es una mala práctica que reduce la legibilidad del código: hace que sea confuso saber si se está utilizando el campo o la variable.

```cs class Foo
{
  public int myField;

  public void DoSomething()
  {
    int myField = 0;  // Noncompliant
    ...
  }
}
```





# Se deben eliminar los pares de paréntesis redundantes.

El uso de paréntesis, incluso aquellos que no se requieren para imponer un orden de operaciones deseado, puede aclarar la intención detrás de un fragmento de código.

```cs if (a && ((x + y > 0))) // Noncompliant
{
  //...
}

return ((x + 1));  // Noncompliant
```

```cs if (a && (x + y > 0))
{
  //...
}

return x + 1;

return (x + 1);
```





# El árbol de herencia de las clases no debe ser demasiado profundo.

La herencia es sin duda uno de los conceptos más valiosos en la programación orientada a objetos.

Esta regla plantea un problema cuando el árbol de herencia, a partir de Objeto, tiene una profundidad mayor que la permitida.





# Los bloques de código anidados no deben dejarse vacíos

La mayoría de las veces, un bloque de código está vacío cuando realmente falta un fragmento de código.

```cs for (int i = 0; i < 42; i++){}  // Empty on purpose or missing piece of code ?
```

Cuando un bloque contiene un comentario, este bloque no se considera vacío.





# Los métodos no deben tener demasiados parámetros.

Una larga lista de parámetros puede indicar que se debe crear una nueva estructura para envolver los numerosos parámetros o que la función está haciendo demasiadas cosas.

Con un número máximo de 4 parámetros:

```cs public void doSomething(int param1, int param2, int param3, string param4, long param5)
{
...
}
```

```cs public void doSomething(int param1, int param2, int param3, string param4)
{
...
}
```





# Las declaraciones "if" colapsables deben combinarse

Fusionar colapsable si las declaraciones aumentan la legibilidad del código.

```cs if (condition1)
{
  if (condition2)
  {
    ...
  }
}
```

```cs if (condition1 && condition2)
{
  ...
}
```





# Los campos mutables no deben ser "public static"

Los campos mutables no deben ser "public static"

Esta regla plantea problemas para los campos estáticos públicos con un tipo que hereda / implementa System.Array o System.Collections.Generic.ICollection <T>.

```cs public class A
{
  public static string[] strings1 = {"first","second"};  // Noncompliant
  public static List<String> strings3 = new List<String>();  // Noncompliant
  // ...
}
```

```cs public class A
{
  protected static string[] strings1 = {"first","second"};
  protected static List<String> strings3 = new List<String>();
  // ...
}
```

No se informa de ningún problema:





# Los campos no deben tener accesibilidad pública.

Los campos públicos en las clases públicas no respetan el principio de encapsulación y tienen tres desventajas principales:

Al usar campos privados y propiedades públicas (establecer y obtener), se evitan las modificaciones no autorizadas.

Tenga en cuenta que debido a las optimizaciones en propiedades simples, los campos públicos proporcionan muy poca ganancia de rendimiento.

```cs public class Foo
{
    public int instanceData = 32; // Noncompliant
}
```

```cs public class Foo
{
    private int instanceData = 32;

    public int InstanceData
    {
        get { return instanceData; }
 set { instanceData = value ; }
    }
}
```

Los campos marcados como de solo lectura o const son ignorados por esta regla.

Esta regla ignora los campos dentro de las clases o estructuras anotadas con el atributo StructLayoutAttribute.





# Las colecciones vacías no deben ser accedidas o iteradas

Cuando una colección está vacía, no tiene sentido acceder o iterarla.

Esta regla plantea un problema cuando se hace un uso de una colección vacía distinta de las siguientes llamadas ignoradas: Add, AddRange, Equals, GetHashCode.

```cs var strings = new List<string>();

strings.Remove("bar");  // Noncompliant

if (strings.Contains("foo")) {}  // Noncompliant

foreach (var str in strings) {}  // Noncompliant
```





# Los campos mutables y no privados no deben ser "de solo lectura"

El uso de la palabra clave readonly en un campo significa que no se puede cambiar después de la inicialización.

Esta regla plantea un problema cuando un campo no privado y de solo lectura es una matriz o colección.

```cs public class MyClass
{
  public readonly string[] strings;  // Noncompliant

  // ...
```

```cs public class MyClass
{
  public string[] strings;

  // ...
```

Esta regla plantea un problema cuando un campo no privado y de solo lectura es una matriz o colección.

```cs public class MyClass
{
  private readonly string[] strings;

  // ...
```





# "string.ToCharArray ()" no debe llamarse de forma redundante

ToCharArray se puede omitir cuando la operación en la matriz podría haberse realizado directamente en la cadena, como cuando se iteran sobre los caracteres en una cadena, y al acceder a un carácter en una cadena a través de un índice de matriz.

```cs string str = "some string";
foreach (var c in str.ToCharArray()) // Noncompliant
{
  // ...
}
```

```cs string str = "some string";
foreach (var c in str)
{
  // ...
}
```





# "base.Equals" no debe usarse para verificar la igualdad de referencia en "Igual a" si "base" no es "objeto"

"base.Equals" no debe usarse para verificar la igualdad de referencia en "Igual a" si "base" no es "objeto"

Esta regla plantea un problema si se usa base.Equals () pero la base no es un objeto.

```cs class Base
{
  private int baseField;

  public override bool Equals(object other)
  {
    if (base.Equals(other)) // Okay; base is object
    {
      return true;
    }

    return this.baseField == ((Base)other).baseField;
  }
}

class Derived : Base
{
  private int derivedField;

  public override bool Equals(object other)
  {
    if (base.Equals(other))  // Noncompliant
    {
      return true;
    }

    return this.derivedField == ((Derived)other).derivedField;
  }
}
```

```cs class Base
{
  private int baseField;

  public override bool Equals(object other)
  {
    if (object.ReferenceEquals(this, other))  // base.Equals is okay here, but object.ReferenceEquals is better
    {
      return true;
    }

    return this.baseField == ((Base)other).baseField;
  }
}

class Derived : Base
{
  private int derivedField;

  public override bool Equals(object other)
  {
    if (object.ReferenceEquals(this, other))
    {
      return true;
    }

    return base.Equals(other) && this.derivedField == ((Derived)other).derivedField;
  }
}
```





# Las asignaciones de propiedades no deben realizarse para campos de "solo lectura" que no estén restringidos a tipos de referencia

Si bien las propiedades de un campo de tipo de referencia de solo lectura pueden cambiarse después de la inicialización, las de un campo de valor de solo lectura, como una estructura, no pueden cambiarse.

Si el miembro podría ser una clase o una estructura, la asignación a sus propiedades podría ser poco confiable, trabajando algunas veces pero otras no.

```cs interface IPoint
{
  int X { get; set; }
  int Y { get; set; }
}

class PointManager<T> where T: IPoint
{
  readonly T point;  // this could be a struct
  public PointManager(T point)
  {
    this.point = point;
  }

  public void MovePointVertically(int newX)
  {
    point.X = newX; //Noncompliant; if point is a struct, then nothing happened
    Console.WriteLine(point.X);
  }
}
```

```cs interface IPoint
{
  int X { get; set; }
  int Y { get; set; }
}

class PointManager<T> where T : IPoint
{
  readonly T point;  // this could be a struct
  public PointManager(T point)
  {
    this.point = point;
  }

  public void MovePointVertically(int newX) // assignment has been removed
  {
    Console.WriteLine(point.X);
  }
}
```

Si el miembro podría ser una clase o una estructura, la asignación a sus propiedades podría ser poco confiable, trabajando algunas veces pero otras no.

```cs interface IPoint
{
  int X { get; set; }
  int Y { get; set; }
}

class PointManager<T> where T : class, IPoint
{
  readonly T point;  // this can only be a class
  public PointManager(T point)
  {
    this.point = point;
  }

  public void MovePointVertically(int newX)
  {
    point.X = newX;  // this assignment is guaranteed to work
    Console.WriteLine(point.X);
  }
}
```





# Las enumeraciones de banderas deben inicializar explícitamente todos sus miembros

Las enumeraciones de banderas no deben confiar en el idioma para inicializar los valores de sus miembros.

En su lugar, 0 y potencias de dos (es decir, 1, 2, 4, 8, 16, ...) deben usarse para inicializar explícitamente todos los miembros.

```cs [Flags]
enum FruitType    // Noncompliant
{
  None,
  Banana,
  Orange,
  Strawberry
}
class Program
{
    static void Main()
    {
        var bananaAndStrawberry = FruitType.Banana | FruitType.Strawberry;
        // Will display only Strawberry!
        Console.WriteLine(bananaAndStrawberry.ToString());
    }
}
```

```cs [Flags]
enum FruitType
{
  None = 0,
  Banana = 1,
  Orange = 2,
  Strawberry = 4
}
class Program
{
    static void Main()
    {
        var bananaAndStrawberry = FruitType.Banana | FruitType.Strawberry;
        // Will display Banana and Strawberry, as expected.
        Console.WriteLine(bananaAndStrawberry.ToString());
    }
}
```

La inicialización predeterminada de 0, 1, 2, 3, 4, ... coincide con 0, 1, 2, 4, 8 ... en los primeros tres valores, por lo que no se informa de ningún problema si los tres primeros miembros de la enumeración son





# "GetHashCode" no debe hacer referencia a campos mutables

GetHashCode se usa para archivar un objeto en un Diccionario o Hashtable.

```cs public class Person
{
  public int age;
  public string name;

  public override int GetHashCode()
  {
    int hash = 12;
    hash += this.age.GetHashCode(); // Noncompliant
    hash += this.name.GetHashCode(); // Noncompliant
    return hash;
  }
```

```cs public class Person
{
  public readonly DateTime birthday;
  public string name;

  public override int GetHashCode()
  {
    int hash = 12;
    hash += this.birthday.GetHashCode();
    return hash;
  }
```





# Los resultados de la división entera no deben asignarse a variables de punto flotante

Cuando la división se realiza en ints, el resultado siempre será un int.

```cs static void Main()
{
  decimal dec = 3/2; // Noncompliant
  Method(3/2); // Noncompliant
}

static void Method(float f) { }
```

```cs static void Main()
{
  decimal dec = (decimal)3/2;
  Method(3.0F/2);
}

static void Method(float f) { }
```





# Los números integrales no deben desplazarse en cero o más que su número de bits-1

Cambiar un número integral por 0 es equivalente a no hacer nada, pero hace que el código sea confuso para los mantenedores.

Si el primer operando es un int o uint (cantidad de 32 bits), el conteo de cambios viene dado por los cinco bits de orden inferior del segundo operando.

Tenga en cuenta que el número integral con una cantidad inferior a 32 bits (por ejemplo, short, ushort ...) se convierte implícitamente a int antes de la operación de cambio, por lo que se aplica la regla para int / uint.

Si el primer operando es largo o largo (cantidad de 64 bits), el conteo de cambios viene dado por los seis bits de orden inferior del segundo operando.

```cs public void Main()
{
    short s = 1;
    short shortShift1 = (short)(s << 0); // Noncompliant
    short shortShift1 = (short)(s << 16); // Compliant as short will be cast to int (16 is between 0 and 31)
    short shortShift3 = (short)(s << 32); // Noncompliant, this is equivalent to shifting by 1

    int i = 1;
    int intShift1 = i << 0; // Noncompliant
    int intShift2 = i << 32; // Noncompliant, this is equivalent to shifting by 1

    long lg = 1;
    long longShift1 = lg << 0; // Noncompliant
    long longShift2 = lg << 64; // Noncompliant, this is equivalent to shifting by 1
}
```

```cs public void Main()
{
    short s = 1;
    short shortShift1 = s;
    short shortShift1 = (short)(s << 16);
    short shortShift3 = (short)(s << 1);

    int i = 1;
    var intShift1 = i;
    var intShift2 = i << 1;

    long lg = 1;
    var longShift1 = lg;
    var longShift2 = lg << 1;
}
```

Esta regla no plantea un problema cuando el cambio por cero es obviamente por razones estéticas:

```cs bytes[loc+0] = (byte)(value >> 8);
bytes[loc+1] = (byte)(value >> 0);
```





# "Equals (Object)" y "GetHashCode ()" deben sobrescribirse en pares

Existe un contrato entre Equals (objeto) y GetHashCode (): si dos objetos son iguales según el método Equals (objeto), llamar a GetHashCode () en cada uno de ellos debe dar el mismo resultado.

Para cumplir con el contrato, Equals (objeto) y GetHashCode () deben ser ambos heredados o ambos anulados.

```cs class MyClass {    // Noncompliant - should also override "hashCode()"

  @Override
  public boolean equals(Object obj) {
    /* ... */
  }

}
```

```cs class MyClass {    // Compliant

  @Override
  public boolean equals(Object obj) {
    /* ... */
  }

  @Override
  public int hashCode() {
    /* ... */
  }

}
```





# El uso de cookies es sensible a la seguridad

El uso de cookies es sensible a la seguridad.

Los atacantes pueden usar herramientas ampliamente disponibles para leer y modificar cookies, por lo tanto:

Esta regla marca el código que lee o escribe cookies.

Usted está en riesgo si responde afirmativamente a cualquiera de esas preguntas.

Las cookies solo deben utilizarse para gestionar la sesión del usuario.

No intente codificar información confidencial en un formato no legible para las personas antes de escribirlas en una cookie.

Desinfecte toda la información leída de una cookie antes de usarla.

El uso de cookies solo para las ID de sesión no las hace seguras.

```cs // === .Net Framework ===

HttpCookie myCookie = new HttpCookie("UserSettings");
myCookie["CreditCardNumber"] = "1234 1234 1234 1234"; // Questionable; sensitive data stored
myCookie.Values["password"] = "5678"; // Questionable
myCookie.Value = "mysecret"; // Questionable
...
Response.Cookies.Add(myCookie);

if (Request.Cookies["myCookie"] != null && Request.Cookies["myCookie"]["myValue"] != null) // Questionable; reading a cookie's value
{
    string value = Request.Cookies["myCookie"]["myValue"]; // Questionable
    value = Request.Cookies["myCookie"].Values["myValue"]; // Questionable
}

string value2 = Request.Cookies["myCookie2"].Value; // Questionable


// === .Net Core ===

Response.Headers.Add("Set-Cookie", ...); // Questionable
Response.Cookies.Append("mykey", "myValue"); // Questionable

Request.Cookies; // Questionable
```





# La creación de cookies sin el indicador "seguro" es sensible a la seguridad

El atributo "seguro" evita que las cookies se envíen a través de conexiones de texto sin formato, como HTTP, donde serían fácilmente escuchadas.

```cs HttpCookie myCookie = new HttpCookie("UserSettings");
myCookie.Secure = false; // Noncompliant; explicitly set to false
...
Response.Cookies.Add(myCookie);
```

```cs HttpCookie myCookie = new HttpCookie("UserSettings"); // Noncompliant; the default value of 'Secure' is used (=false)
...
Response.Cookies.Add(myCookie);
```

```cs HttpCookie myCookie = new HttpCookie("UserSettings");
myCookie.Secure = true; // Compliant
...
Response.Cookies.Add(myCookie);
```





# Los sufijos literales deben ser mayúsculas

El uso de sufijos literales en mayúsculas elimina la ambigüedad potencial entre "1" (dígito 1) y "l" (letra el) para declarar literales.

```cs const long b = 0l;      // Noncompliant
```

```cs const long b = 0L;
```





# Los campos "estáticos" deben inicializarse en línea

Cuando un constructor estático no tiene otro propósito que inicializar campos estáticos, tiene un costo de rendimiento innecesario porque el compilador genera una comprobación antes de cada invocación de constructor de instancia o método estático.

En su lugar, la inicialización en línea es muy recomendable.

```cs namespace myLib
{
  public class Foo
  {
    static int i;
    static string s;

    static Foo() // Noncompliant
    {
      i = 3;
      ResourceManager sm =  new ResourceManager("strings", Assembly.GetExecutingAssembly());
      s = sm.GetString("mystring");
    }
  }
}
```

```cs namespace myLib
{
  public class Foo
  {
    static int i =3;
    static string s = InitString();

    static string InitString()
    {
      ResourceManager sm = new ResourceManager("strings", Assembly.GetExecutingAssembly());
      return sm.GetString("mystring");
    }
  }
}
```





# Las clases que proporcionan "Igual a (<T>)" deben implementar "IEquatable <T>"

La interfaz de IEquatable <T> solo tiene un método: Equals (<T>).

Nota **: Las clases que implementan IEquatable <T> también deben estar selladas.

```cs class MyClass  // Noncompliant
{
  public override bool Equals(object other)
  {
    //...
  }
}
```

```cs class MyClass  // Noncompliant
{
  public bool Equals(MyClass other)
  {
    //...
  }
}
```

```cs class MyClass : IEquatable<T>  // Noncompliant
{
}
```

```cs sealed class MyClass : IEquatable<MyClass>
{
  public override bool Equals(object other)
  {
    return Equals(other as MyClass);
  }

  public bool Equals(MyClass other)
  {
    //...
  }
}
```





# Las declaraciones de salto no deben ser redundantes

Las declaraciones de salto, como retorno, ruptura de rendimiento, goto y continuar, le permiten cambiar el flujo predeterminado de la ejecución del programa, pero las declaraciones de salto que dirigen el flujo de control a la dirección original son solo una pérdida de pulsaciones de teclas.

```cs void Foo()
{
  goto A; // Noncompliant
  A:
  while (condition1)
  {
    if (condition2)
    {
      continue; // Noncompliant
    }
    else
    {
      DoTheThing();
    }
  }
  return; // Noncompliant; this is a void method
}
```

```cs void Foo()
{
  while (condition1)
  {
    if (!condition2)
    {
      DoTheThing();
    }
  }
}
```





# Los valores del inicializador de miembros no deben ser redundantes

Los campos, las propiedades y los eventos pueden inicializarse en línea o en el constructor.

```cs class Person
{
  int age = 42; // Noncompliant
  public Person(int age)
  {
    this.age = age;
  }
}
```

```cs class Person
{
  int age;
  public Person(int age)
  {
    this.age = age;
  }
}
```

Esta regla no informa un problema si no todos los constructores inicializan el campo.





# Los miembros no asignados deben ser eliminados

Campos y propiedades automáticas que nunca se asignan para mantener los valores predeterminados para sus tipos.

```cs class MyClass
{
  private int field; // Noncompliant, shouldn't it be initialized? This way the value is always default(int), 0.
  private int Property { get; set; }  // Noncompliant
  public void Print()
  {
    Console.WriteLine(field); //Will always print 0
    Console.WriteLine(Property); //Will always print 0
  }
}
```

```cs class MyClass
{
  private int field = 1;
  private int Property { get; set; } = 42;
  public void Print()
  {
    field++;
    Console.WriteLine(field);
    Console.WriteLine(Property);
  }
}
```





# Se deben omitir las cláusulas de "casos" vacíos que caen en el "defecto"

Las cláusulas de casos vacíos que caen en el valor predeterminado son inútiles.

```cs switch(ch)
{
  case 'a' :
    HandleA();
    break;
  case 'b' :
    HandleB();
    break;
  case 'c' :  // Noncompliant
  default:
    HandleTheRest();
    break;
}
```

```cs switch(ch)
{
  case 'a' :
    HandleA();
    break;
  case 'b' :
    HandleB();
    break;
  default:
    HandleTheRest();
    break;
}
```





# Los parámetros con los atributos "[DefaultParameterValue]" también deben estar marcados "[Opcional]"

No tiene sentido proporcionar un valor predeterminado para un parámetro si los llamantes deben proporcionar un valor para él de todos modos.

```cs public void MyMethod([DefaultParameterValue(5)] int j) //Noncompliant, useless
{
  Console.WriteLine(j);
}
```

```cs public void MyMethod(int j = 5)
{
  Console.WriteLine(j);
}
```

No tiene sentido proporcionar un valor predeterminado para un parámetro si los llamantes deben proporcionar un valor para él de todos modos.

```cs public void MyMethod([DefaultParameterValue(5)][Optional] int j)
{
  Console.WriteLine(j);
}
```





# Las interfaces no deben simplemente heredarse de las interfaces base con miembros en conflicto.

Cuando una interfaz se hereda de dos interfaces que definen un miembro con el mismo nombre, intentar acceder a ese miembro a través de la interfaz derivada generará el error de compilación CS0229 Ambigüedad entre 'IBase1.SomeProperty' y 'IBase2.SomeProperty'.

Entonces, en cambio, cada persona que llama se verá obligada a enviar instancias de la interfaz derivada a una u otra de sus interfaces base para resolver la ambigüedad y poder acceder al miembro.

Entonces, en cambio, cada persona que llama se verá obligada a enviar instancias de la interfaz derivada a una u otra de sus interfaces base para resolver la ambigüedad y poder acceder al miembro.

```cs public interface IBase1
{
  string SomeProperty { get; set; }
}

public interface IBase2
{
  string SomeProperty { get; set; }
}

public interface IDerived : IBase1, IBase2 // Noncompliant, accessing IDerived.SomeProperty is ambiguous
{
}

public class MyClass : IDerived
{
  // Implements both IBase1.SomeProperty and IBase2.SomeProperty
  public string SomeProperty { get; set; } = "Hello";

  public static void Main()
  {
    MyClass myClass = new MyClass();
    Console.WriteLine(myClass.SomeProperty); // Writes "Hello" as expected
    Console.WriteLine(((IBase1)myClass).SomeProperty); // Writes "Hello" as expected
    Console.WriteLine(((IBase2)myClass).SomeProperty); // Writes "Hello" as expected
    Console.WriteLine(((IDerived)myClass).SomeProperty); // Error CS0229 Ambiguity between 'IBase1.SomeProperty' and 'IBase2.SomeProperty'
  }
}
```

```cs public interface IDerived : IBase1, IBase2
{
  new string SomeProperty { get; set; }
}

public class MyClass : IDerived
{
  // Implements IBase1.SomeProperty, IBase2.SomeProperty and IDerived.SomeProperty
  public string SomeProperty { get; set; } = "Hello";

  public static void Main()
  {
    MyClass myClass = new MyClass();
    Console.WriteLine(myClass.SomeProperty); // Writes "Hello" as expected
    Console.WriteLine(((IBase1)myClass).SomeProperty); // Writes "Hello" as expected
    Console.WriteLine(((IBase2)myClass).SomeProperty); // Writes "Hello" as expected
    Console.WriteLine(((IDerived)myClass).SomeProperty); // Writes "Hello" as expected
  }
}
```

Entonces, en cambio, cada persona que llama se verá obligada a enviar instancias de la interfaz derivada a una u otra de sus interfaces base para resolver la ambigüedad y poder acceder al miembro.

```cs public interface IBase1
{
  string SomePropertyOne { get; set; }
}

public interface IBase2
{
  string SomePropertyTwo { get; set; }
}

public interface IDerived : IBase1, IBase2
{
}
```





# Las variables no deben compararse con los valores que están a punto de asignarse.

No tiene sentido comparar una variable con el valor que está a punto de asignarla.

```cs if (x != a)  // Noncompliant; why bother?
{
  x = a;
}
```

```cs x = a;
```

Las propiedades se excluyen de esta regla porque podrían tener efectos secundarios y la eliminación de la verificación podría provocar efectos secundarios no deseados.





# Los métodos no deben devolver constantes.

No tiene sentido forzar la sobrecarga de una llamada de método para un método que siempre devuelve el mismo valor constante.

Esta regla plantea un problema si en los métodos que contienen solo una declaración: la devolución de un valor constante.

```cs int GetBestNumber()
{
  return 12;  // Noncompliant
}
```

```cs const int BestNumber = 12;
```

Esta regla plantea un problema si en los métodos que contienen solo una declaración: la devolución de un valor constante.

```cs static readonly int BestNumber = 12;
```





# Los nombres de atributo, EventArgs y tipo de excepción deben terminar con el tipo extendido

La adhesión a las convenciones de nomenclatura estándar hace que su código no solo sea más legible, sino también más utilizable.

Esta regla plantea un problema cuando las clases que extienden Atributo, EventArgs o Excepción, no terminan con sus nombres de clase principales.

```cs class AttributeOne : Attribute  // Noncompliant
{
}
```

```cs class FirstAttribute : Attribute
{
}
```

Si la clase base directa de una clase no sigue la convención, entonces no se informa de ningún problema en la clase en sí, independientemente de si se ajusta o no a la convención.

```cs class Timeout : Exception // Noncompliant
{
}
class ExtendedTimeout : Timeout // Ignored; doesn't conform to convention, but the direct base doesn't conform either
{
}
```





# Los espacios de nombres no deben estar vacíos

Los espacios de nombres sin líneas de código abarrotan un proyecto y deben eliminarse.

```cs namespace MyEmptyNamespace // Noncompliant
{

}
```





# Se debe usar "string.IsNullOrEmpty"

El uso de string.Equals para determinar si una cadena está vacía es significativamente más lento que usar string.IsNullOrEmpty () o buscar string.Length == 0. string.IsNullOrEmpty () es claro y conciso, y por lo tanto preferido a laborioso, error

```cs "".Equals(name); // Noncompliant
!name.Equals(""); // Noncompliant
name.Equals(string.Empty); // Noncompliant
```

```cs name != null && name.Length > 0 // Compliant but more error prone
!string.IsNullOrEmpty(name)
string.IsNullOrEmpty(name)
```





# Se deben proporcionar implementaciones para los métodos "parciales".

Se deben proporcionar implementaciones para los métodos "parciales".

Esta regla plantea un problema para los métodos parciales para los cuales no se puede encontrar ninguna implementación en el ensamblaje.

```cs partial class C
{
  partial void M(); //Noncompliant

  void OtherM()
  {
    M(); //Noncompliant. Will be removed.
  }
}
```





# No se deben hacer lanzamientos duplicados.

Debido a que el operador is realiza una conversión si el objeto no es nulo, el uso es para verificar el tipo y luego emitir el mismo argumento para ese tipo, necesariamente realiza dos conversiones.

```cs if (x is Fruit)  // Noncompliant
{
  var f = (Fruit)x; // or x as Fruit
  // ...
}
```

```cs var f = x as Fruit;
if (f != null)
{
  // code
}
```





# Los métodos no deben devolver valores que nunca se usan.

Los métodos privados están claramente destinados a ser usados solo dentro de su propio alcance.





# Los métodos privados están claramente destinados a ser usados solo dentro de su propio alcance.

Atributos de información de la persona que llama: CallerFilePathAttribute y CallerLineNumberAttribute proporcionan una forma de obtener información sobre la persona que llama un método a través de parámetros opcionales.

```cs void TraceMessage(string message,
  [CallerFilePath] string filePath = null,
  [CallerLineNumber] int lineNumber = 0)
{
  /* ... */
}

void MyMethod()
{
  TraceMessage("my message", "A.B.C.Foo.cs", 42); // Noncompliant
}
```

```cs void TraceMessage(string message,
  [CallerFilePath] string filePath = "",
  [CallerLineNumber] int lineNumber = 0)
{
  /* ... */
}

void MyMethod()
{
  TraceMessage("my message");
}
```

CallerMemberName no se verifica para evitar falsos positivos con aplicaciones WPF / UWP.





# Las llamadas a métodos no deberían resolverse de forma ambigua a sobrecargas con "params"

Las reglas para la resolución de métodos son complejas y quizás no sean entendidas correctamente por todos los codificadores.

Esta regla plantea un problema cuando una invocación se resuelve en una declaración de método con params, pero también podría resolverse en otro método no params.

```cs public class MyClass
{
  private void Format(string a, params object[] b) { }

  private void Format(object a, object b, object c) { }
}

// ...
MyClass myClass = new MyClass();

myClass.Format("", null, null); //Noncompliant, resolves to the first Format with params, but was that intended?
```





# Las cláusulas de "captura" deberían hacer más que volver a lanzar

Una cláusula de captura que solo repite la excepción capturada tiene el mismo efecto que omitir la captura por completo y dejar que salte automáticamente, pero con más código y el detrimento adicional de dejar a los mantenedores rascándose la cabeza.

Tales cláusulas deben eliminarse o completarse con la lógica apropiada.

```cs string s = "";
try
{
  s = File.ReadAllText(fileName);
}
catch (Exception e)  // Noncompliant
{
  throw;
}
```

```cs string s = "";
try
{
  s = File.ReadAllText(fileName);
}
catch (Exception e) // Compliant
{
  logger.LogError(e);
  throw;
}
```

Tales cláusulas deben eliminarse o completarse con la lógica apropiada.

```cs string s = File.ReadAllText(fileName);
```

Esta regla no generará problemas para los bloques catch con solo lanzarlos dentro si van seguidos de un bloque catch para un tipo de excepción más general que hace más que solo volver a generar la excepción.

```cs var s = ""
try
{
    s = File.ReadAllText(fileName);
}
catch (IOException) // Compliant, if removed will change the logic
{
    throw;
}
catch (Exception)  // Compliant, does more than just rethrow
{
    logger.LogError(e);
    throw;
}
```





# Los nombres de los tipos de enumeración no deben tener sufijos "Indicadores" o "Enum"

La información de que un tipo de enumeración es en realidad una enumeración o un conjunto de indicadores no debe estar duplicada en su nombre.

```cs enum FooFlags // Noncompliant
{
    Foo = 1
    Bar = 2
    Baz = 4
}
```

```cs enum Foo
{
    Foo = 1
    Bar = 2
    Baz = 4
}
```





# Los tipos de enumeración deben cumplir con una convención de nomenclatura

Las convenciones de nomenclatura compartidas permiten que los equipos colaboren de manera eficiente.

La configuración por defecto es la recomendada por Microsoft:

La configuración por defecto es la recomendada por Microsoft:

```cs public enum foo // Noncompliant
{
    FooValue = 0
}
```

Con la expresión regular predeterminada para enums de enumeración: ^ ([A-Z] {1,3} [a-z0-9] +) * ([A-Z] {2})? S $

```cs [Flags]
public enum Option // Noncompliant
{
    None = 0,
    Option1 = 1,
    Option2 = 2
}
```

```cs public enum Foo
{
    FooValue = 0
}
```

```cs [Flags]
public enum Options
{
    None = 0,
    Option1 = 1,
    Option2 = 2
}
```





# Las propiedades triviales deben ser auto-implementadas.

Las propiedades triviales, que no incluyen lógica, pero la configuración y la obtención de un campo de respaldo deben convertirse en propiedades implementadas automáticamente, para obtener un código más limpio y más legible.

```cs public class Car
{
  private string _make;
  public string Make // Noncompliant
  {
    get { return _make; }
    set { _make = value; }
  }
}
```

```cs public class Car
{
  public string Make { get; set; }
}
```





# La verificación del tipo de tiempo de ejecución debe ser simplificada

Para comprobar el tipo de un objeto hay varias opciones:

Si es necesario comparar los tipos calculados en el tiempo de ejecución:

Dependiendo de si el tipo es devuelto por una llamada GetType () o typeof (), IsAssignableFrom () y IsInstanceOfType () pueden simplificarse.

Finalmente, el uso de las construcciones de lenguaje más concisas para la verificación de tipos hace que el código sea más legible, por lo que

```cs class Fruit { }
sealed class Apple : Fruit { }

class Program
{
  static void Main()
  {
    var apple = new Apple();
    var b = apple != null && apple.GetType() == typeof (Apple); // Noncompliant
    b = typeof(Apple).IsInstanceOfType(apple); // Noncompliant
    if (apple != null)
    {
      b = typeof(Apple).IsAssignableFrom(apple.GetType()); // Noncompliant
    }
    var appleType = typeof (Apple);
    if (apple != null)
    {
      b = appleType.IsAssignableFrom(apple.GetType()); // Noncompliant
    }

    Fruit f = apple;
    if (f as Apple != null) // Noncompliant
    {
    }
    if (apple is Apple) // Noncompliant
    {
    }
  }
}
```

```cs class Fruit { }
sealed class Apple : Fruit { }

class Program
{
  static void Main()
  {
    var apple = new Apple();
    var b = apple is Apple;
    b = apple is Apple;
    b = apple is Apple;
    var appleType = typeof(Apple);
    b = appleType.IsInstanceOfType(apple);

    Fruit f = apple;
    if (f is Apple)
    {
    }
    if (apple != null)
    {
    }
  }
}
```

Llamar a GetType en un objeto de tipo Nullable <T> devuelve el parámetro de tipo genérico subyacente T, por lo que no se puede simplificar una comparación con typeof (Nullable <T>) para usar el operador is, que no hace diferencia entre T y

```cs int? i = 42;
bool condition = i.GetType() == typeof(int?); // false;
condition = i is int?; // true
```

No se informa de ningún problema en expr es expresiones T si cualquiera de los operandos de es operador es un tipo de valor.





# Los cheques booleanos no deben invertirse

Es innecesariamente complejo invertir el resultado de una comparación booleana.

```cs if ( !(a == 2)) { ...}  // Noncompliant
bool b = !(i < 10);  // Noncompliant
```

```cs if (a != 2) { ...}
bool b = (i >= 10);
```





# La lista de herencia no debe ser redundante

Una entrada de la lista de herencia es redundante si:

Dichas declaraciones redundantes deben eliminarse porque innecesariamente desordenan el código y pueden ser confusas.

```cs public class MyClass : Object  // Noncompliant

enum MyEnum : int  // Noncompliant
```

```cs public class MyClass

enum MyEnum
```





# No se deben utilizar moldes redundantes.

Las expresiones de reparto innecesarias hacen que el código sea más difícil de leer y entender.

```cs public int Example(int i)
{
  return (int) (i + 42); // Noncompliant
}
public IEnumerable<int> ExampleCollection(IEnumerable<int> coll)
{
  return coll.Reverse().OfType<int>(); // Noncompliant
}
```

```cs public int Example(int i)
{
  return i + 42;
}
public IEnumerable<int> ExampleCollection(IEnumerable<int> coll)
{
  return coll.Reverse();
}
```





# Las cadenas no deben ser concatenadas usando '+' en un bucle

StringBuilder es más eficiente que la concatenación de cadenas, especialmente cuando el operador se repite una y otra vez como en los bucles.

```cs string str = "";
for (int i = 0; i < arrayOfStrings.Length ; ++i)
{
  str = str + arrayOfStrings[i];
}
```

```cs StringBuilder bld = new StringBuilder();
for (int i = 0; i < arrayOfStrings.Length; ++i)
{
  bld.Append(arrayOfStrings[i]);
}
string str = bld.ToString();
```





# Las variables locales no utilizadas deben ser eliminadas

Si se declara una variable local pero no se usa, es un código muerto y debe eliminarse.

```cs public int NumberOfMinutes(int hours)
{
  int seconds = 0;   // seconds is never used
  return hours * 60;
}
```

```cs public int NumberOfMinutes(int hours)
{
  return hours * 60;
}
```

No se informan los recursos creados localmente no utilizados en una declaración de uso.

```cs using(var t = new TestTimer()) // t never used, but compliant.
{
  //...
}
```





# Los campos privados que solo se usan como variables locales en los métodos deberían convertirse en variables locales

Cuando el valor de un campo privado siempre se asigna a los métodos de una clase antes de ser leído, entonces no se está utilizando para almacenar información de clase.

```cs public class Foo
{
  private int singularField;

  public void DoSomething(int x)
  {
    singularField = x + 5;

    if (singularField == 0) { /* ... */ }
  }
}
```

```cs public class Foo
{
  public void DoSomething(int x)
  {
    int localVariable = x + 5;

    if (localVariable == 0) { /* ... */ }
  }
}
```





# Se debe utilizar un bucle "while" en lugar de un bucle "for"

Cuando solo se define la expresión de condición en un bucle for, y faltan las expresiones de inicialización e incremento, se debe usar un bucle while en su lugar para aumentar la legibilidad.

```cs for (;condition;) { /*...*/ }
```

```cs while (condition) { /*...*/ }
```





# "Igual a" y los operadores de comparación deben ser anulados al implementar "IComparable"

Cuando implementas IComparable o IComparable <T> en una clase, también debes anular Equals (objeto) y sobrecargar los operadores de comparación (==,! =, <, <=,>,> =).

Esta regla plantea un problema cuando una clase implementa IComparable sin anular también Equals (objeto) y los operadores de comparación.

```cs public class Foo: IComparable  // Noncompliant
{
  public int CompareTo(object obj) { /* ... */ }
}
```

```cs public class Foo: IComparable
{
  public int CompareTo(object obj) { /* ... */ }
  public override bool Equals(object obj)
  {
    var other = obj as Foo;
    if (object.ReferenceEquals(other, null))
    {
      return false;
    }
    return this.CompareTo(other) == 0;
  }
  public int GetHashCode() { /* ... */ }
  public static bool operator == (Foo left, Foo right)
  {
    if (object.ReferenceEquals(left, null))
    {
      return object.ReferenceEquals(right, null);
    }
    return left.Equals(right);
  }
  public static bool operator > (Foo left, Foo right)
  {
    return Compare(left, right) > 0;
  }
  public static bool operator < (Foo left, Foo right)
  {
    return Compare(left, right) < 0;
  }
  public static bool operator != (Foo left, Foo right)
  {
    return !(left == right);
  }
}
```





# Los miembros que sobrescriben deben hacer más que simplemente llamar al mismo miembro en la clase base

Anular un método solo para llamar al mismo método desde la clase base sin realizar ninguna otra acción es inútil y engañoso.

NOTA: En algunos casos, podría ser peligroso agregar o eliminar anulaciones vacías, ya que podrían estar rompiendo cambios.

```cs public override void Method() // Noncompliant
{
  base.Method();
}
```

```cs public override void Method()
{
  //do something else
}
```

Si hay un atributo en cualquier nivel de la cadena de reemplazo, el miembro reemplazado se ignora.

```cs public class Base
{
  [Required]
  public virtual string Name { get; set; }
}

public class Derived : Base
{
  public override string Name
  {
    get
    {
      return base.Name;
    }
    set
    {
      base.Name = value;
    }
  }
}
```

Si hay un comentario de documentación sobre el método de reemplazo, se ignorará:

```cs public class Foo : Bar
{
    /// <summary>
    /// Keep this method for backwards compatibility.
    /// </summary>
    public override void DoSomething()
    {
        base.DoSomething();
    }
}
```





# "Cualquier ()" se debe usar para probar el vacío

El uso de .Count () para probar el vacío funciona, pero el uso de .Any () hace que la intención sea más clara y que el código sea más legible.

El uso de .Count () para probar el vacío funciona, pero el uso de .Any () hace que la intención sea más clara y que el código sea más legible.

El uso de .Count () para probar el vacío funciona, pero el uso de .Any () hace que la intención sea más clara y que el código sea más legible.

```cs private static bool HasContent(IEnumerable<string> strings)
{
  return strings.Count() > 0;  // Noncompliant
}

private static bool HasContent2(IEnumerable<string> strings)
{
  return strings.Count() >= 1;  // Noncompliant
}

private static bool IsEmpty(IEnumerable<string> strings)
{
  return strings.Count() == 0;  // Noncompliant
}
```

```cs private static bool HasContent(IEnumerable<string> strings)
{
  return strings.Any();
}

private static bool IsEmpty(IEnumerable<string> strings)
{
  return !strings.Any();
}
```





# Los literales booleanos no deben ser redundantes.

Los literales booleanos redundantes deben eliminarse de las expresiones para mejorar la legibilidad.

```cs if (booleanMethod() == true) { /* ... */ }
if (booleanMethod() == false) { /* ... */ }
if (booleanMethod() || false) { /* ... */ }
doSomething(!false);
doSomething(booleanMethod() == true);

booleanVariable = booleanMethod() ? true : false;
booleanVariable = booleanMethod() ? true : exp;
booleanVariable = booleanMethod() ? false : exp;
booleanVariable = booleanMethod() ? exp : true;
booleanVariable = booleanMethod() ? exp : false;

for (var x = 0; true; x++)
{
 ...
}
```

```cs if (booleanMethod()) { /* ... */ }
if (!booleanMethod()) { /* ... */ }
if (booleanMethod()) { /* ... */ }
doSomething(true);
doSomething(booleanMethod());

booleanVariable = booleanMethod();
booleanVariable = booleanMethod() || exp;
booleanVariable = !booleanMethod() && exp;
booleanVariable = !booleanMethod() || exp;
booleanVariable = booleanMethod() && exp;

for (var x = 0; ; x++)
{
 ...
}
```





# Las declaraciones vacías deben ser eliminadas

Las declaraciones vacías, es decir, se suelen introducir por error, por ejemplo porque:

```cs void doSomething()
{
  ; // Noncompliant - was used as a kind of TODO marker
}

void doSomethingElse()
{
  Console.WriteLine("Hello, world!");;  // Noncompliant - double ;
  ...
  // Rarely, they are used on purpose as the body of a loop. It is a bad practice to
  // have side-effects outside of the loop:
  for (int i = 0; i < 3; Console.WriteLine(i), i++); // Noncompliant
  ...
}
```

```cs void doSomething()
{
}

void doSomethingElse()
{
  Console.WriteLine("Hello, world!");
  ...
  for (int i = 0; i < 3; i++)
  {
    Console.WriteLine(i);
   }
  ...
}
```





# Los URI no deben ser codificados

La codificación de un URI dificulta la prueba de un programa: los literales de la ruta no siempre son portátiles en todos los sistemas operativos, es posible que no exista una ruta absoluta determinada en un entorno de prueba específico, una URL de Internet específica puede no estar disponible al ejecutar las pruebas, sistemas de archivos del entorno de producción

Además, incluso si los elementos de un URI se obtienen dinámicamente, la portabilidad aún puede ser limitada si los delimitadores de ruta están codificados.

Esta regla plantea un problema cuando los URI o los delimitadores de ruta están codificados.

Esta regla no plantea un problema cuando se pasa una ruta virtual ASP.NET como un argumento a uno de los siguientes:





# Los tipos deben ser nombrados en PascalCase

Las convenciones de nomenclatura compartidas permiten que los equipos colaboren de manera eficiente.

```cs class my_class {...}
class SOMEName42 {...}
```

```cs class MyClass {...}
class SomeName42 {...}
```

La regla ignora los tipos que están marcados con ComImportAttribute o InterfaceTypeAttribute.

```cs class Some_Name___42 {...} // valid in test
class Some_name___42 {...} // still not valid
class Some_Name_XC {...} // invalid because of XC, should be Some_Name_Xc
```





# Seguimiento de los usos de las etiquetas "TODO"

Las etiquetas TODO se usan comúnmente para marcar lugares donde se requiere algo más de código, pero que el desarrollador desea implementar más adelante.

A veces, el desarrollador no tendrá tiempo o simplemente se olvidará de volver a esa etiqueta.

Esta regla sirve para rastrear esas etiquetas y garantizar que no pasen desapercibidas.

```cs private void DoSomething()
{
  // TODO
}
```





# Las clases con miembros "IDisposable" deben implementar "IDisposable"

Se debe desechar un objeto IDisponible (hay algunas excepciones raras en las que no está bien, especialmente la Tarea).

Se debe desechar un objeto IDisponible (hay algunas excepciones raras en las que no está bien, especialmente la Tarea).

Se debe desechar un objeto IDisponible (hay algunas excepciones raras en las que no está bien, especialmente la Tarea).

En el segundo caso, la forma más segura para que la clase se asegure de que se llame a Dispose es llamarlo en su propia función de Dispose y, por lo tanto, ser IDisposable.

```cs public class ResourceHolder   // Noncompliant; doesn't implement IDisposable
{
  private FileStream fs;  // This member is never Disposed
  public void OpenResource(string path)
  {
    this.fs = new FileStream(path, FileMode.Open); // I create the FileStream, I'm owning it
  }
  public void CloseResource()
  {
    this.fs.Close();
  }
}
```

```cs public class ResourceHolder : IDisposable
{
  private FileStream fs;
  public void OpenResource(string path)
  {
    this.fs = new FileStream(path, FileMode.Open); // I create the FileStream, I'm owning it
  }
  public void CloseResource()
  {
    this.fs.Close();
  }

  public void Dispose()
  {
    this.fs.Dispose();
  }
}
```





# Las llamadas a métodos "asíncronos" no deberían estar bloqueando

Hacer llamadas de bloqueo a métodos asíncronos transforma algo que estaba destinado a ser asíncrono en un bloque síncrono.

Según la documentación de MSDN:

La causa raíz de este interbloqueo se debe a la forma en que los contextos de los manejadores esperan.

```cs public static class DeadlockDemo
{
    private static async Task DelayAsync()
    {
        await Task.Delay(1000);
    }

    // This method causes a deadlock when called in a GUI or ASP.NET context.
    public static void Test()
    {
        // Start the delay.
        var delayTask = DelayAsync();
        // Wait for the delay to complete.
        delayTask.Wait(); // Noncompliant
    }
}
```

```cs public static class DeadlockDemo
{
    private static async Task DelayAsync()
    {
        await Task.Delay(1000);
    }

    public static async Task TestAsync()
    {
        // Start the delay.
        var delayTask = DelayAsync();
        // Wait for the delay to complete.
        await delayTask;
    }
}
```





# Las pruebas deben incluir afirmaciones

Un caso de prueba sin aseveraciones solo garantiza que no se produzcan excepciones.

Esta regla genera una excepción cuando no se encuentran aserciones de cualquiera de los siguientes marcos en una prueba:

```cs [TestMethod]
public void MyMethod_WhenSomething_ExpectsSomething()
{
    var myClass = new Class();
    var result = myClass.GetFoo();
}
```

```cs [TestMethod]
public void MyMethod_WhenSomething_ExpectsSomething()
{
    var myClass = new Class();
    var result = myClass.GetFoo();
    Assert.IsTrue(result);
}
```





# Los campos de clase secundaria no deben sombrear los campos de clase padre

Tener una variable con el mismo nombre en dos clases no relacionadas está bien, pero haga lo mismo dentro de una jerarquía de clases y obtendrá confusión en el mejor de los casos, en el peor de los casos caos.

```cs public class Fruit
{
  protected Season ripe;
  protected Color flesh;

  // ...
}

public class Raspberry : Fruit
{
  private bool ripe; // Noncompliant
  private static Color FLESH; // Noncompliant
}
```

```cs public class Fruit
{
  protected Season ripe;
  protected Color flesh;

  // ...
}

public class Raspberry : Fruit
{
  private bool ripened;
  private static Color FLESH_COLOR;
}
```

Esta regla ignora los campos del mismo nombre que son estáticos tanto en la clase principal como en la secundaria.

```cs public class Fruit
{
  private Season ripe;
  // ...
}

public class Raspberry : Fruit
{
  private Season ripe;  // Compliant as parent field 'ripe' is anyway not visible from Raspberry
  // ...
}
```





# "async" y "await" no deben usarse como identificadores

Desde C # 5.0, async y await son palabras clave contextuales.

```cs int await = 42; // Noncompliant
```

```cs int someOtherName = 42;
```





# Desde C # 5.0, async y await son palabras clave contextuales.

Desde C # 5.0, async y await son palabras clave contextuales.

Esta regla se debe alimentar con el texto del encabezado que se espera al comienzo de cada archivo.

El headerFormat debe terminar con una línea vacía si desea tener una línea vacía entre el encabezado del archivo y la primera línea de su archivo fuente (usando, espacio de nombres ...).

Por ejemplo, si desea que el archivo de origen se vea así

```cs // Copyright (c) SonarSource. All Rights Reserved. Licensed under the LGPL License.  See License.txt in the project root for license information.

namespace Foo
{
}
```

Por ejemplo, si desea que el archivo de origen se vea así

```cs // Copyright (c) SonarSource. All Rights Reserved. Licensed under the LGPL License.  See License.txt in the project root for license information.
```

```cs /*
 * SonarQube, open source software quality management tool.
 * Copyright (C) 2008-2013 SonarSource
 * mailto:contact AT sonarsource DOT com
 *
 * SonarQube is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * SonarQube is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
```





# Los métodos de salida no deben ser llamados

Calling Environment.Exit (exitCode) o Application.Exit () finaliza el proceso y devuelve un código de salida al sistema operativo.

Cada uno de estos métodos debe usarse con extremo cuidado y solo cuando la intención es detener toda la aplicación.

```cs Environment.Exit(0);
Application.Exit();
```

Estos métodos son ignorados dentro de Main.





# El algoritmo de cifrado AES se debe utilizar con el modo seguro

Los algoritmos de cifrado se pueden utilizar con varios modos.

En ambos casos, se debe preferir el Modo Galois / Contador (GCM) sin relleno.

Esta regla plantea un problema cuando se detecta cualquiera de los siguientes CipherMode: ECB, CBC, OFB, CFB, CTS.

```cs AesManaged aes = new AesManaged
{
  KeySize = 128,
  BlockSize = 128,
  Mode = CipherMode.OFB, // Noncompliant
  Padding = PaddingMode.PKCS7
};
```





# Los constructores de serialización deben estar asegurados.

Debido a que los constructores de serialización asignan e inicializan objetos, las comprobaciones de seguridad que están presentes en los constructores regulares también deben estar presentes en un constructor de serialización.

Esta regla plantea un problema cuando un tipo implementa la interfaz System.Runtime.Serialization.ISerializable, no es un delegado o una interfaz, se declara en un ensamblaje que permite llamadas entrantes parcialmente confiables y tiene un constructor que toma un System.Runtime.Serialization.SerializationInfo

```cs using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Permissions;

[assembly: AllowPartiallyTrustedCallersAttribute()]
namespace MyLibrary
{
    [Serializable]
    public class Foo : ISerializable
    {
        private int n;

        [FileIOPermissionAttribute(SecurityAction.Demand, Unrestricted = true)]
        public Foo()
        {
           n = -1;
        }

        protected Foo(SerializationInfo info, StreamingContext context) // Noncompliant
        {
           n = (int)info.GetValue("n", typeof(int));
        }

        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
           info.AddValue("n", n);
        }
    }
}
```

```cs using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Permissions;

[assembly: AllowPartiallyTrustedCallersAttribute()]
namespace MyLibrary
{
    [Serializable]
    public class Foo : ISerializable
    {
        private int n;

        [FileIOPermissionAttribute(SecurityAction.Demand, Unrestricted = true)]
        public Foo()
        {
           n = -1;
        }

        [FileIOPermissionAttribute(SecurityAction.Demand, Unrestricted = true)]
        protected Foo(SerializationInfo info, StreamingContext context)
        {
           n = (int)info.GetValue("n", typeof(int));
        }

        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
           info.AddValue("n", n);
        }
    }
}
```





# Los algoritmos hash SHA-1 y Message-Digest no deben usarse en contextos seguros

El algoritmo MD5 y su sucesor, SHA-1, ya no se consideran seguros, porque es demasiado fácil crear colisiones de hash con ellos.

Esta regla hace un seguimiento del uso de los métodos System.Security.Cryptography.CryptoConfig.CreateFromName () y System.Security.Cryptography.HashAlgorithm.Create () para crear una instancia de MD5, DSA, HMACMD5, o SHA / SHASK / SHAX

Considere usar alternativas más seguras, como SHA-256 o SHA-3.

```cs var hashProvider1 = new MD5CryptoServiceProvider(); //Noncompliant
var hashProvider2 = (HashAlgorithm)CryptoConfig.CreateFromName("MD5"); //Noncompliant
var hashProvider3 = new SHA1Managed(); //Noncompliant
var hashProvider4 = HashAlgorithm.Create("SHA1"); //Noncompliant
```

```cs var hashProvider1 = new SHA256Managed();
var hashProvider2 = (HashAlgorithm)CryptoConfig.CreateFromName("SHA256Managed");
var hashProvider3 = HashAlgorithm.Create("SHA256Managed");
```





# Las clases deben "disponer" de los miembros de los propios métodos de "disponer"

Es posible en un IDisposible llamar a Dispose en miembros de la clase desde cualquier método, pero el contrato de Dispose es que limpiará todos los recursos no administrados.

```cs public class ResourceHolder : IDisposable
{
  private FileStream fs;
  public void OpenResource(string path)
  {
    this.fs = new FileStream(path, FileMode.Open);
  }
  public void CloseResource()
  {
    this.fs.Close();
  }

  public void CleanUp()
  {
    this.fs.Dispose(); // Noncompliant; Dispose not called in class' Dispose method
  }

  public void Dispose()
  {
    // method added to satisfy demands of interface
  }
}
```

```cs public class ResourceHolder : IDisposable
{
  private FileStream fs;
  public void OpenResource(string path)
  {
    this.fs = new FileStream(path, FileMode.Open);
  }
  public void CloseResource()
  {
    this.fs.Close();
  }

  public void Dispose()
  {
    this.fs.Dispose();
  }
}
```





# Los métodos de interfaz deben ser invocables por tipos derivados

Cuando un tipo base implementa explícitamente un método de interfaz pública, ese método solo es accesible en tipos derivados a través de una referencia a la instancia actual (a saber, esta).

Esta regla plantea un problema cuando un tipo no sellado, visible externamente proporciona una implementación de método explícita de una interfaz pública y no proporciona un método alternativo, visible externamente con el mismo nombre.

```cs public interface IMyInterface
{
    void MyMethod();
}

public class Foo : IMyInterface
{
    void IMyInterface.MyMethod() // Noncompliant
    {
        MyMethod();
    }

    void MyMethod()
    {
        // Do something ...
    }
}

public class Bar : Foo, IMyInterface
{
    public void MyMethod()
    {
        // Can't access base.MyMethod()
        // ((IMyInterface)this).MyMethod() would be a recursive call
    }
}
```

```cs public interface IMyInterface
{
    void MyMethod();
}

public class Foo : IMyInterface
{
    void IMyInterface.MyMethod()
    {
        MyMethod();
    }

    protected void MyMethod() // or public
    {
        // Do something ...
    }
}

public class Bar : Foo, IMyInterface
{
    public void MyMethod()
    {
        // Do something
        base.MyMethod();
    }
}
```

Esta regla no informa una infracción para una implementación explícita de IDisposable.Disponer cuando se proporciona un método Close () o System.IDisposable.Dispose (Boolean) visible externamente.





# Los campos de clase secundaria no deben diferir de los campos de clase principal solo por mayúsculas

Tener un campo en una clase secundaria con un nombre que difiera del campo de una clase primaria solo por el uso de mayúsculas seguramente causará confusión.

```cs public class Fruit
{
  protected string plantingSeason;
  //...
}

public class Raspberry : Fruit
{
  protected string plantingseason;  // Noncompliant
  // ...
}
```

```cs public class Fruit
{
  protected string plantingSeason;
  //...
}

public class Raspberry : Fruit
{
  protected string whenToPlant;
  // ...
}
```

O

```cs public class Fruit
{
  protected string plantingSeason;
  //...
}

public class Raspberry : Fruit
{
  // field removed; parent field will be used instead
  // ...
}
```





# Los punteros a la memoria no administrada no deben ser visibles

Los tipos IntPtr y UIntPtr se utilizan para acceder a la memoria no administrada, generalmente para usar las bibliotecas C o C ++.

```cs using System;

namespace MyLibrary
{
  public class MyClass
  {
    public IntPtr myPointer;  // Noncompliant
    protected UIntPtr myOtherPointer; // Noncompliant
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class MyClass
  {
    private IntPtr myPointer;
    protected readonly UIntPtr myOtherPointer;
  }
}
```





# Los patrones de números deben ser regulares

El uso de caracteres de puntuación para separar subgrupos en un número puede hacer que el número sea más legible.

Esta regla plantea un problema cuando los guiones bajos (_) se utilizan para dividir un número en subgrupos irregulares.

```cs int duos = 1_00_00;
int million = 1_000_00_000;  // Noncompliant
int thousand = 1000;
int tenThousand = 100_00;  // Noncompliant
```





# Los parámetros "out" y "ref" no deben usarse

Pasar un parámetro por referencia, que es lo que sucede cuando usa los modificadores de parámetro out o ref, significa que el método recibirá un puntero al argumento, en lugar del argumento en sí.

Esta regla plantea un problema cuando se usa out o ref en un parámetro no opcional en un método público.

```cs public void GetReply(
         ref MyClass input, // Noncompliant
         out string reply)  // Noncompliant
{ ... }
```

```cs public string GetReply(MyClass input)
{ ... }

public bool TryGetReply(MyClass input, out string reply)
{ ... }

public ReplyData GetReply(MyClass input)
{ ... }

internal void GetReply(ref MyClass input, out string reply)
{ ... }
```

Esta regla no planteará problemas para:

Esta regla no planteará problemas para:

Esta regla no planteará problemas para:





# Las variables locales sin cambios deben ser "const"

Marcar una variable que no se modifica después de la inicialización const es una indicación para los futuros mantenedores de que "no, esto no se actualiza y se supone que no lo está".

```cs public bool Seek(int[] input)
{
  int target = 32;  // Noncompliant
  foreach (int i in input)
  {
    if (i == target)
    {
      return true;
    }
  }
  return false;
}
```

```cs public bool Seek(int[] input)
{
  const int target = 32;
  foreach (int i in input)
  {
    if (i == target)
    {
      return true;
    }
  }
  return false;
}
```





# Se debe utilizar "ConfigureAwait (falso)"

Después de que una tarea esperada se haya ejecutado, puede continuar la ejecución en el subproceso original que llama o en cualquier subproceso arbitrario.

Esta regla plantea un problema cuando el código en una biblioteca de clases espera una Tarea y continúa la ejecución en el hilo de llamada original.

```cs var response = await httpClient.GetAsync(url);  // Noncompliant
```

```cs var response = await httpClient.GetAsync(url).ConfigureAwait(false);
```





# Las instancias de "interfaz" no se deben convertir en tipos concretos.

La necesidad de emitir desde una interfaz a un tipo concreto indica que algo está mal con las abstracciones en uso, es probable que falte algo en la interfaz.

```cs public interface IMyInterface
{
  void DoStuff();
}

public class MyClass1 : IMyInterface
{
  public int Data { get { return new Random().Next(); } }

  public void DoStuff()
  {
    // TODO...
  }
}

public static class DowncastExampleProgram
{
  static void EntryPoint(IMyInterface interfaceRef)
  {
    MyClass1 class1 = (MyClass1)interfaceRef;  // Noncompliant
    int privateData = class1.Data;

    class1 = interfaceRef as MyClass1;  // Noncompliant
    if (class1 != null)
    {
      // ...
    }
  }
}
```

Lanzar objetos no plantea un problema, ya que nunca puede fallar.

```cs static void EntryPoint(IMyInterface interfaceRef)
{
  var o = (object)interfaceRef;
  ...
}
```





# Los valores booleanos literales no deben usarse en aserciones

No hay razón para usar valores booleanos literales en las aserciones.

```cs bool b = true;
NUnit.Framework.Assert.AreEqual(true, b);
Xunit.Assert.NotSame(true, b);
Microsoft.VisualStudio.TestTools.UnitTesting.Assert.AreEqual(true, b);
System.Diagnostics.Debug.Assert(true);
```





# Los parámetros opcionales no deben ser utilizados

El mecanismo de sobrecarga se debe utilizar en lugar de los parámetros opcionales por varias razones:

```cs void Notify(string company, string office = "QJZ") // Noncompliant
{
}
```

```cs void Notify(string company)
{
  Notify(company, "QJZ");
}
void Notify(string company, string office)
{
}
```

La regla ignora los métodos no visibles externamente.





# Miembros constantes públicos no deben ser utilizados

Los miembros constantes se copian en tiempo de compilación en los sitios de llamada, en lugar de buscarlos en tiempo de ejecución.

Como ejemplo, supongamos que tiene una biblioteca con un miembro de Versión constante establecido en 1.0 y una aplicación cliente vinculada a ella.

Esto significa que debe usar constantes para mantener valores que, por definición, nunca cambiarán, como Cero.

Esta regla solo informa de problemas en campos constantes públicos, a los que se puede acceder desde fuera del ensamblaje de definición.

```cs public class Foo
{
    public const double Version = 1.0;           // Noncompliant
}
```

```cs public class Foo
{
    public static double Version
    {
      get { return 1.0; }
    }
}
```





# No debe utilizarse covarianza de matrices.

La covarianza de la matriz es el principio de que si una conversión de referencia implícita o explícita sale del tipo A a B, entonces existe la misma conversión del tipo de matriz A [] a B [].

Si bien esta conversión de matriz puede ser útil en situaciones de solo lectura para pasar instancias de A [] donde se espera que B [], debe usarse con cuidado, ya que la asignación de una instancia de B en una matriz de A hará que se lance una ArrayTypeMismatchException en

```cs abstract class Fruit { }
class Apple : Fruit { }
class Orange : Fruit { }

class Program
{
  static void Main(string[] args)
  {
    Fruit[] fruits = new Apple[1]; // Noncompliant - array covariance is used
    FillWithOranges(fruits);
  }

  // Just looking at the code doesn't reveal anything suspicious
  static void FillWithOranges(Fruit[] fruits)
  {
    for (int i = 0; i < fruits.Length; i++)
    {
      fruits[i] = new Orange(); // Will throw an ArrayTypeMismatchException
    }
  }
}
```

```cs abstract class Fruit { }
class Apple : Fruit { }
class Orange : Fruit { }

class Program
{
  static void Main(string[] args)
  {
    Orange[] fruits = new Orange[1]; // Compliant
    FillWithOranges(fruits);
  }

  static void FillWithOranges(Orange[] fruits)
  {
    for (int i = 0; i < fruits.Length; i++)
    {
      fruits[i] = new Orange();
    }
  }
}
```





# Se debe usar "nameof"

Debido a que los nombres de los parámetros se pueden cambiar durante la refactorización, no se deben deletrear literalmente en cadenas.

Esta regla plantea un problema cuando cualquier cadena en la declaración de lanzamiento coincide exactamente con el nombre de uno de los parámetros del método.

```cs void DoSomething(int someParameter)
{
    if (someParameter < 0)
    {
        throw new ArgumentException("Bad argument", "someParameter");  // Noncompliant
    }
}
```

```cs void DoSomething(int someParameter)
{
    if (someParameter < 0)
    {
        throw new ArgumentException("Bad argument", nameof(someParameter));
    }
}
```

La regla no plantea ningún problema cuando se usa C # <6.0.





# Los resultados del módulo no deben ser verificados para la igualdad directa

Cuando se calcula el módulo de un número negativo, el resultado será negativo o cero.

```cs public bool IsOdd(int x)
{
  return x % 2 == 1;  // Noncompliant; if x is an odd negative, x % 2 == -1
}
```

```cs public bool IsOdd(int x)
{
  return x %2 != 0;
}
```

Cuando se calcula el módulo de un número negativo, el resultado será negativo o cero.

```cs public bool IsOdd(uint x)
{
  return x %2 == 1;
}
```





# Las cláusulas de incremento de bucle "for" deberían modificar los contadores de los bucles.

Puede ser extremadamente confuso cuando el contador de un bucle for se incrementa fuera de su cláusula de incremento.

```cs for (i = 0; i < 10; j++) // Noncompliant
{
  // ...
}
```

```cs for (i = 0; i < 10; i++)
{
  // ...
}
```





# Las declaraciones de "cambio" no deben estar anidadas

Las estructuras de conmutadores anidadas son difíciles de entender porque puede confundir fácilmente los casos de un conmutador interno como pertenecientes a una declaración externa.

Específicamente, debe estructurar su código para evitar la necesidad de sentencias de cambio anidadas, pero si no puede, entonces considere mover el interruptor interno a otra función.





# Específicamente, debe estructurar su código para evitar la necesidad de sentencias de cambio anidadas, pero si no puede, entonces considere mover el interruptor interno a otra función.

La complejidad ciclomática de los métodos y propiedades no debe exceder un umbral definido.





# Las declaraciones de flujo de control "if", "switch", "for", "foreach", "while", "do" y "try" no deben anidarse demasiado.

Las declaraciones anidadas, switch, for, foreach, while, do y try son ingredientes clave para hacer lo que se conoce como "código Spaghetti".

Tal código es difícil de leer, refactorizar y, por lo tanto, mantener.

Con el umbral predeterminado de 3:

```cs if (condition1) // Compliant - depth = 1
{
  /* ... */
  if (condition2) // Compliant - depth = 2
  {
    /* ... */
    for(int i = 0; i < 10; i++) // Compliant - depth = 3, not exceeding the limit
    {
      /* ... */
      if (condition4) // Noncompliant - depth = 4
      {
        if (condition5) // Depth = 5, exceeding the limit, but issues are only reported on depth = 4
        {
          /* ... */
        }
        return;
      }
    }
  }
}
```





# Las declaraciones "switch / Select" deben contener cláusulas "default / Case Else"

El requisito para una cláusula por defecto final es la programación defensiva.

```cs int foo = 42;
switch (foo) // Noncompliant
{
  case 0:
    Console.WriteLine("foo = 0");
    break;
  case 42:
    Console.WriteLine("foo = 42");
    break;
}
```

```cs int foo = 42;
switch (foo) // Compliant
{
  case 0:
    Console.WriteLine("foo = 0");
    break;
  case 42:
    Console.WriteLine("foo = 42");
    break;
  default:
    throw new InvalidOperationException("Unexpected value foo = " + foo);
}
```





# "if ... else if" las construcciones deben terminar con las cláusulas "else"

Esta regla se aplica siempre que a una instrucción if le sigue una o más instrucciones if;

El requisito para una declaración final es la programación defensiva.

La declaración else debe tomar la acción apropiada o contener un comentario adecuado de por qué no se toma ninguna acción.

```cs if (x == 0)
{
  doSomething();
} else if (x == 1)
{
  doSomethingElse();
}
```

```cs if (x == 0)
{
  doSomething();
} else if (x == 1)
{
  doSomethingElse();
} else
{
  throw new IllegalStateException();
}
```





# Las estructuras de control deben usar llaves.

Las estructuras de control deben usar llaves.

```cs // the two statements seems to be attached to the if statement, but that is only true for the first one:
if (condition)
  ExecuteSomething();
  CheckSomething();
```

```cs if (condition)
{
  ExecuteSomething();
  CheckSomething();
}
```





# Las expresiones no deben ser demasiado complejas.

La complejidad de una expresión se define por el número de &&, ||

La complejidad de una sola expresión no debe ser demasiado alta para mantener el código legible.

Con el valor de umbral predeterminado de 3

```cs if (((condition1 && condition2) || (condition3 && condition4)) && condition5) { ... }
```

```cs if ((MyFirstCondition() || MySecondCondition()) && MyLastCondition()) { ... }
```





# La función de validación de solicitud HTTP de ASP.NET no debe estar deshabilitada

ASP.Net tiene una función para validar las solicitudes HTTP para evitar que el contenido potencialmente peligroso realice un ataque de scripts entre sitios (XSS).

Esta regla plantea un problema si un método con parámetros está marcado con System.Web.Mvc.HttpPostAttribute y no System.Web.Mvc.ValidateInputAttribute (true).

```cs public class FooBarController : Controller
{
    [HttpPost] // Noncompliant
    [ValidateInput(false)]
    public ActionResult Purchase(string input)
    {
        return Foo(input);
    }

    [HttpPost] // Noncompliant
    public ActionResult PurchaseSomethingElse(string input)
    {
        return Foo(input);
    }
}
```

```cs public class FooBarController : Controller
{
    [HttpPost]
    [ValidateInput(true)] // Compliant
    public ActionResult Purchase(string input)
    {
        return Foo(input);
    }
}
```

Los métodos sin parámetros marcados con System.Web.Mvc.HttpPostAttribute no provocarán este problema.





# Se debe utilizar la lógica de cortocircuito para evitar las referencias erróneas de puntero nulo en condicionales

Cuando se invierte el operador de igualdad en una prueba nula o el operador lógico que lo sigue, el código tiene la apariencia de realizar una prueba nula segura del objeto antes de anular la referencia.

```cs if (str == null && str.Length == 0)
{
  Console.WriteLine("String is empty");
}

if (str != null || str.Length > 0)
{
  Console.WriteLine("String is not empty");
}
```

```cs if (str == null || str.Length == 0)
{
  Console.WriteLine("String is empty");
}

if (str != null && str.Length > 0)
{
  Console.WriteLine("String is not empty");
}
```

Esta regla está en desuso;





# Los números de punto flotante no deben ser probados para la igualdad

La matemática de punto flotante es imprecisa debido a los desafíos de almacenar tales valores en una representación binaria.

Incluso las asignaciones simples de punto flotante no son simples:

```cs float f = 0.100000001f; // 0.1
double d = 0.10000000000000001; // 0.1
```

(Los resultados variarán según la configuración del compilador y del compilador)

Por lo tanto, el uso de los operadores de igualdad (==) y de desigualdad (! =) En valores flotantes o dobles es casi siempre un error.

Esta regla verifica el uso de pruebas directas e indirectas de igualdad / desigualdad en flotadores y dobles.

```cs float myNumber = 3.146f;
if ( myNumber == 3.146f ) //Noncompliant. Because of floating point imprecision, this will be false
{
  // ...
}

if (myNumber <= 3.146f && mNumber >= 3.146f) // Noncompliant indirect equality test
{
  // ...
}

if (myNumber < 4 || myNumber > 4) // Noncompliant indirect inequality test
{
  // ...
}
```





# Los bloques "if (true) {...}" y "if (false) {...}" son inútiles y deben eliminarse

Los bloques "if (true) {...}" y "if (false) {...}" son inútiles y deben eliminarse

Hay tres causas posibles para la presencia de dicho código:

En cualquiera de estos casos, incondicional si las declaraciones deben ser eliminadas.

```cs if (true)
{
  DoSomething();
}
...
if (false)
{
  DoSomethingElse();
}
```

```cs DoSomething();
...
```

Esta regla está en desuso;





# Los operadores de incremento (++) y decremento (-) no deben usarse en una llamada de método o mezclarse con otros operadores en una expresión

No se recomienda el uso de operadores de incremento y decremento en las llamadas de método o en combinación con otros operadores aritméticos, porque:

```cs u8a = ++u8b + u8c--;
foo = bar++ / 4;
```

La siguiente secuencia es más clara y por lo tanto más segura:

```cs ++u8b;
u8a = u8b + u8c;
u8c--;
foo = bar / 4;
bar++;
```





# Los valores duplicados no deben pasarse como argumentos

Hay casos válidos para pasar una variable varias veces en la misma llamada de método, pero normalmente hacerlo es un error, y algo más fue pensado para uno de los argumentos.

```cs if (Compare(point.X, point.X) != 0) // Noncompliant
{
  //...
}

if (DoSomething(GetNextValue(), GetNextValue()))  // Noncompliant
{
  // ...
}
```

```cs if (Compare(point.X, point.Y) != 0)
{
  //...
}

var v1 = GetNextValue();
var v2 = GetNextValue();
if (DoSomething(v1, v2))
{
  // ...
}
```

Esta regla está en desuso y, finalmente, se eliminará.





# Los nombres de propiedades no deben coincidir con los métodos de obtención

Las propiedades y el método Get deben tener nombres que los hagan claramente distinguibles.

Esta regla plantea un problema cuando el nombre de un miembro público o protegido comienza con "Obtener" y, de lo contrario, coincide con el nombre de una propiedad pública o protegida.

```cs using System;

namespace MyLibrary
{
    public class Foo
    {
        public DateTime Date
        {
            get { return DateTime.Today; }
        }

        public string GetDate() // Noncompliant
        {
            return this.Date.ToString();
        }
    }
}
```

```cs using System;

namespace MyLibrary
{
    public class Foo
    {
        public DateTime Date
        {
            get { return DateTime.Today; }
        }

        public string GetDateAsString()
        {
            return this.Date.ToString();
        }
    }
}
```





# Las configuraciones regionales se deben establecer para los tipos de datos

Cuando crea un DataTable o DataSet, debe establecer la configuración regional explícitamente.

Cuando crea un DataTable o DataSet, debe establecer la configuración regional explícitamente.

```cs using System;
using System.Data;

namespace MyLibrary
{
    public class Foo
    {
        public DataTable CreateTable()
        {
            DataTable table = new DataTable("Customers"); // Noncompliant table.Locale not set
            DataColumn key = table.Columns.Add("ID", typeof(Int32));

            key.AllowDBNull = false;
            key.Unique = true;
            table.Columns.Add("LastName", typeof(String));
            table.Columns.Add("FirstName", typeof(String));
            return table;
        }
    }
}
```

```cs using System;
using System.Data;
using System.Globalization;

namespace MyLibrary
{
    public class Foo
    {
        public DataTable CreateTable()
        {
            DataTable table = new DataTable("Customers");
            table.Locale = CultureInfo.InvariantCulture;
            DataColumn key = table.Columns.Add("ID", typeof(Int32));

            key.AllowDBNull = false;
            key.Unique = true;
            table.Columns.Add("LastName", typeof(String));
            table.Columns.Add("FirstName", typeof(String));
            return table;
        }
    }
}
```





# Los literales no deben pasarse como parámetros localizados

Los literales de cadena incrustados en el código fuente no se localizarán correctamente.

Esta regla plantea un problema cuando una cadena literal se pasa como un parámetro o una propiedad y uno o más de los siguientes casos son verdaderos:

```cs using System;
using System.Globalization;
using System.Reflection;
using System.Windows.Forms;

[assembly: NeutralResourcesLanguageAttribute("en-US")]
namespace MyLibrary
{
    public class Foo
    {
        public void SetHour(int hour)
        {
            if (hour < 0 || hour > 23)
            {
                MessageBox.Show("The valid range is 0 - 23."); // Noncompliant
            }
        }
    }
}
```

```cs using System;
using System.Globalization;
using System.Reflection;
using System.Resources;
using System.Windows.Forms;



[assembly: NeutralResourcesLanguageAttribute("en-US")]
namespace MyLibrary
{
    public class Foo
    {
        ResourceManager rm;
        public Foo()
        {
            rm = new ResourceManager("en-US", Assembly.GetExecutingAssembly());
        }

        public void SetHour(int hour)
        {
            if (hour < 0 || hour > 23)
            {
                MessageBox.Show(
                rm.GetString("OutOfRangeMessage", CultureInfo.CurrentUICulture));
            }
        }
    }
}
```





# Los operadores deben estar sobrecargados constantemente

Al implementar sobrecargas de operadores, es muy importante asegurarse de que todos los operadores y métodos relacionados sean coherentes en su implementación.

Se deben seguir las siguientes pautas:

Esta regla plantea un problema cuando cualquiera de estas pautas no se sigue en un tipo visible públicamente (público, protegido o protegido interno).

```cs using System;

namespace MyLibrary
{
  public class Foo // Noncompliant
  {
    private int left;
    private int right;

    public Foo(int l, int r)
    {
      this.left = l;
      this.right = r;
    }

    public static Foo operator +(Foo a, Foo b)
    {
      return new Foo(a.left + b.left, a.right + b.right);
    }

    public static Foo operator -(Foo a, Foo b)
    {
      return new Foo(a.left - b.left, a.right - b.right);
    }
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    private int left;
    private int right;

    public Foo(int l, int r)
    {
      this.left = l;
      this.right = r;
    }

    public static Foo operator +(Foo a, Foo b)
    {
      return new Foo(a.left + b.left, a.right + b.right);
    }

    public static Foo operator -(Foo a, Foo b)
    {
      return new Foo(a.left - b.left, a.right - b.right);
    }

    public static bool operator ==(Foo a, Foo b)
    {
      return (a.left == b.left && a.right == b.right);
    }

    public static bool operator !=(Foo a, Foo b)
    {
      return !(a == b);
    }

    public override bool Equals(Object obj)
    {
      Foo a = obj as Foo;
      if (a == null)
        return false;
      return this == a;
    }

    public override int GetHashCode()
    {
       return (this.left * 10) + this.right;
    }
  }
}
```





# Las firmas de métodos no deben contener tipos genéricos anidados

Un tipo anidado es un argumento de tipo que también es un tipo genérico.

```cs using System;
using System.Collections.Generic;

namespace MyLibrary
{
  public class Foo
  {
    public void DoSomething(ICollection<ICollection<int>> outerCollect) // Noncompliant
    {
    }
  }
}
```





# Deben usarse argumentos "System.Uri" en lugar de cadenas

Las representaciones de cadenas de URI o URL son propensas a analizar y codificar errores que pueden provocar vulnerabilidades.

Esta regla plantea un problema cuando un método llamado tiene un parámetro de cadena con un nombre que contiene "uri", "Uri", "urna", "Urna", "url" o "Url" y el tipo de declaración contiene una sobrecarga correspondiente que lleva

Cuando hay una opción entre dos sobrecargas que difieren solo con respecto a la representación de un URI, el usuario debe elegir la sobrecarga que toma un argumento System.Uri.

```cs using System;

namespace MyLibrary
{
   public class Foo
   {
      public void FetchResource(string uriString) { }
      public void FetchResource(Uri uri) { }

      public string ReadResource(string uriString, string name, bool isLocal) { }
      public string ReadResource(Uri uri, string name, bool isLocal) { }

      public void Main() {
        FetchResource("http://www.mysite.com"); // Noncompliant
        ReadResource("http://www.mysite.com", "foo-resource", true); // Noncompliant
      }
   }
}
```

```cs using System;

namespace MyLibrary
{
   public class Foo
   {
      public void FetchResource(string uriString) { }
      public void FetchResource(Uri uri) { }

      public string ReadResource(string uriString, string name, bool isLocal) { }
      public string ReadResource(Uri uri, string name, bool isLocal) { }

      public void Main() {
        FetchResource(new Uri("http://www.mysite.com"));
        ReadResource(new Uri("http://www.mysite.com"), "foo-resource", true);
      }
   }
}
```





# Las propiedades de la colección deben ser de solo lectura.

Una propiedad de colección escribible puede reemplazarse por una colección completamente diferente.

Esta regla plantea un problema cuando una propiedad de escritura visible externamente es de un tipo que implementa System.Collections.ICollection o System.Collections.Generic.ICollection <T>.

```cs using System;
using System.Collections;

namespace MyLibrary
{
  public class Foo
  {
    List<string> strings;

    public List<string> SomeStrings
    {
      get { return strings; }
      set { strings = value; } // Noncompliant
    }
  }
}
```

```cs using System;
using System.Collections;

namespace MyLibrary
{
  public class Foo
  {
    List<string> strings;

    public readonly List<string> SomeStrings
    {
      get { return strings; }
    }
  }
}
```

Esta regla no plantea problemas para string, Array y PermissionSet.





# Los tipos desechables deben declarar finalizadores.

Esta regla plantea un problema cuando un tipo desechable contiene campos de los siguientes tipos y no implementa un finalizador:

```cs using System;
using System.Runtime.InteropServices;

namespace MyLibrary
{
  public class Foo : IDisposable // Noncompliant: Doesn't have a finalizer
  {
    private IntPtr myResource;
    private bool disposed = false;

    protected virtual void Dispose(bool disposing)
    {
      if (!disposed)
      {
        // Dispose of resources held by this instance.
        FreeResource(myResource);
        disposed = true;

        // Suppress finalization of this disposed instance.
        if (disposing)
        {
          GC.SuppressFinalize(this);
        }
      }
    }

    public void Dispose() {
      Dispose(true);
    }
  }
}
```

```cs using System;
using System.Runtime.InteropServices;

namespace MyLibrary
{
  public class Foo : IDisposable
  {
    private IntPtr myResource;
    private bool disposed = false;

    protected virtual void Dispose(bool disposing)
    {
      if (!disposed)
      {
        // Dispose of resources held by this instance.
        FreeResource(myResource);
        disposed = true;

        // Suppress finalization of this disposed instance.
        if (disposing)
        {
          GC.SuppressFinalize(this);
        }
      }
    }

    ~Foo()
    {
      Dispose(false);
    }
  }
}
```





# Las sobrecargas de URI de cadena deben llamar sobrecargas de "System.Uri"

Las representaciones de cadenas de URI o URL son propensas a analizar y codificar errores que pueden provocar vulnerabilidades.

Esta regla plantea un problema cuando dos sobrecargas difieren solo por el parámetro cadena / Uri y la sobrecarga de cadena no llama a la sobrecarga de Uri.

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {
      public void FetchResource(string uriString) // Noncompliant
      {
         // No calls to FetResource(Uri)
      }

      public void FetchResource(Uri uri) { }
   }
}
```

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {
      public void FetchResource(string uriString)
      {
          FetchResource(new Uri(uriString));
      }

      public void FetchResource(Uri uri) { }
   }
}
```





# Las propiedades de URI no deben ser cadenas

Las representaciones de cadenas de URI o URL son propensas a analizar y codificar errores que pueden provocar vulnerabilidades.

Esta regla plantea un problema cuando una propiedad es un tipo de cadena y su nombre contiene "uri", "Uri", "urna", "Urna", "url" o "Url".

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {
      string myUri;

      public string MyUri // Noncompliant
      {
         get { return myURI; }
         set { myUri = value; }
      }
   }
}
```

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {
      Uri myUri;

      public Uri MyUri
      {
         get { return myURI; }
         set { myUri = value; }
      }
   }
}
```





# Los valores de retorno de URI no deben ser cadenas

Las representaciones de cadenas de URI o URL son propensas a analizar y codificar errores que pueden provocar vulnerabilidades.

Esta regla plantea un problema cuando un método tiene un tipo de retorno de cadena y su nombre contiene "Uri", "Urna" o "Url" o comienza con "uri", "urna" o "url".

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {
      public string GetParentUri() // Noncompliant
      {
         return "http://www.mysite.com";
      }
   }
}
```

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {

      public Uri GetParentUri()
      {
         return new URI("http://www.mysite.com");
      }
   }
}
```





# Los parámetros URI no deben ser cadenas

Las representaciones de cadenas de URI o URL son propensas a analizar y codificar errores que pueden provocar vulnerabilidades.

Esta regla plantea problemas cuando un método tiene un parámetro de cadena con un nombre que contiene "uri", "Uri", "urna", "Urna", "url" o "Url", y el tipo no declara una sobrecarga correspondiente

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {

      public void FetchResource(string uriString) { } // Noncompliant
   }
}
```

```cs using System;

namespace MyLibrary
{
   public class MyClass
   {

      public void FetchResource(string uriString)
      {
          FetchResource(new Uri(uriString));
      }

      public void FetchResource(Uri uri) { }
   }
}
```





# Los atributos personalizados deben marcarse con "System.AttributeUsageAttribute"

Al definir atributos personalizados, System.AttributeUsageAttribute se debe utilizar para indicar dónde se puede aplicar el atributo.

```cs using System;

namespace MyLibrary
{

   public sealed class MyAttribute :Attribute // Noncompliant
   {
      string text;

      public MyAttribute(string myText)
      {
         text = myText;
      }
      public string Text
      {
         get
         {
            return text;
         }
      }
   }
}
```

```cs using System;

namespace MyLibrary
{

   [AttributeUsage(AttributeTargets.Class | AttributeTargets.Enum | AttributeTargets.Interface | AttributeTargets.Delegate)]
   public sealed class MyAttribute :Attribute
   {
      string text;

      public MyAttribute(string myText)
      {
         text = myText;
      }
      public string Text
      {
         get
         {
            return text;
         }
      }
   }
}
```





# Las asambleas deben especificar explícitamente la visibilidad de COM

Las asambleas deben indicar explícitamente si deben ser visibles para COM o no.

Tenga en cuenta que la visibilidad de COM se puede anular para tipos y miembros individuales.

```cs using System;

namespace MyLibrary  // Noncompliant
{
}
```

```cs using System;

[assembly: System.Runtime.InteropServices.ComVisible(false)]
namespace MyLibrary
{
}
```





# Los conjuntos deben estar marcados como compatibles con CLS

Los ensamblajes deben cumplir con la Especificación de lenguaje común (CLS) para poder ser utilizados en todos los lenguajes de programación.

```cs using System;

[assembly:CLSCompliant(true)]
namespace MyLibrary
{
}
```





# Las instancias de "Generic.List" no deben formar parte de las API públicas

System.Collections.Generic.List <T> es una colección genérica que está diseñada para el rendimiento y no la herencia.

Esta regla plantea un problema cada vez que se expone un System.Collections.Generic.List <T>:

```cs namespace Foo
{
   public class Bar
   {
      public List<T> Method1(T arg) // Noncompliant
      {
           //...
      }
   }
}
```

```cs namespace Foo
{
   public class Bar
   {
      public Collection<T> Method1(T arg)
      {
           //...
      }
   }
}
```





# Las colecciones deben implementar la interfaz genérica.

NET Framework 2.0 introdujo la interfaz genérica System.Collections.Generic.IEnumerable <T> y debería preferirse a las interfaces más antiguas y no genéricas.

Esta regla plantea un problema cuando un tipo público implementa System.Collections.IEnumerable.

```cs using System;
using System.Collections;

public class MyData
{
  public MyData()
  {
  }
}

public class MyList : CollectionBase // Noncompliant
{
  public void Add(MyData data)
  {
    InnerList.Add(data);
  }

  // ...
}
```

```cs using System;
using System.Collections.ObjectModel;

public class MyData
{
  public MyData()
  {
  }
}

public class MyList : Collection<MyData>
{
  // Implementation...
}
```





# Deben utilizarse controladores de eventos genéricos

Desde .Net Framework versión 2.0 no es necesario declarar un delegado que especifique una clase derivada de System.EventArgs.

Esta regla plantea un problema cuando se utiliza un delegado de estilo antiguo como controlador de eventos.

```cs public class MyEventArgs : EventArgs
{
}

public delegate void MyEventHandler(object sender, MyEventArgs e); // Noncompliant

public class EventProducer
{
  public event MyEventHandler MyEvent;

  protected virtual void OnMyEvent(MyEventArgs e)
  {
    if (MyEvent != null)
    {
      MyEvent(e);
    }
  }
}

public class EventConsumer
{
  public EventConsumer(EventProducer producer)
  {
      producer.MyEvent += HandleEvent;
  }

  private void HandleEvent(object sender, MyEventArgs e)
  {
    // Do something...
  }
}
```

```cs public class MyEventArgs : EventArgs
{
}

public class EventProducer
{
  public event EventHandler<MyEventArgs> MyEvent;

  protected virtual void OnMyEvent(MyEventArgs e)
  {
    if (MyEvent != null)
    {
      MyEvent(e);
    }
  }
}

public class EventConsumer
{
  public EventConsumer(EventProducer producer)
  {
      producer.MyEvent += HandleEvent;
  }

  private void HandleEvent(object sender, MyEventArgs e)
  {
    // Do something...
  }
}
```





# Los manejadores de eventos deben tener la firma correcta

Los manejadores de eventos delegados (es decir, los delegados utilizados como tipo de evento) deben tener una firma muy específica:

Los manejadores de eventos delegados (es decir, los delegados utilizados como tipo de evento) deben tener una firma muy específica:

```cs public delegate void AlarmEventHandler(object s);

public class Foo
{
    public event AlarmEventHandler AlarmEvent; // Noncompliant
}
```

```cs public delegate void AlarmEventHandler(object sender, AlarmEventArgs e);

public class Foo
{
    public event AlarmEventHandler AlarmEvent; // Compliant
}
```

Manipulación y crianza de eventos





# "Assembly.GetExecutingAssembly" no debe llamarse

El uso de Type.Assembly para obtener el ensamblaje actual es casi gratis en términos de rendimiento;

Tenga en cuenta que Assembly.GetExecutingAssembly () es diferente de Type.Assembly porque devuelve dinámicamente el ensamblado que contiene el objeto de inicio de la aplicación actualmente ejecutada.

```cs public class Example
{
   public static void Main()
   {
      Assembly assem = Assembly.GetExecutingAssembly(); // Noncompliant
      Console.WriteLine("Assembly name: {0}", assem.FullName);
   }
}
```

```cs public class Example
{
   public static void Main()
   {
      Assembly assem = typeof(Example).Assembly; // Here we use the type of the current class
      Console.WriteLine("Assembly name: {0}", assem.FullName);
   }
}
```





# Los argumentos de los métodos públicos deben ser validados contra nulos.

Se puede llamar a un método público desde cualquier lugar, lo que significa que debe validar los parámetros para que estén dentro de las restricciones esperadas.

Esta regla plantea un problema cuando un parámetro del método público no se valida con un valor nulo antes de que se elimine la referencia.

```cs public class MyClass
{
    private MyOtherClass other;

    public void Foo(MyOtherClass other)
    {
        this.other = other; // Compliant: other not being dereferenced
    }

    public void Bar(MyOtherClass other)
    {
        this.other = other.Clone(); // Noncompliant
    }
}
```

```cs public class MyClass
{
    private MyOtherClass other;

    public void Foo(MyOtherClass other)
    {
        this.other = other;
    }

    public void Bar(MyOtherClass other)
    {
        if (other != null)
        {
            this.other = other.Clone();
        }
    }
}
```

Para crear un método de validación nulo personalizado, declare un atributo con el nombre ValidatedNotNullAttribute y marque con él el parámetro validado para nulo en su declaración de método:

```cs using System;

public sealed class ValidatedNotNullAttribute : Attribute { }

public static class Guard
{
    public static void NotNull<T>([ValidatedNotNullAttribute] this T value, string name) where T : class
    {
        if (value == null)
            throw new ArgumentNullException(name);
    }
}

public static class Utils
{
    public static string ToUpper(string value)
    {
        Guard.NotNull(value, nameof(value));
        if (value == null)
        {
            return value.ToString();
        }
        return value.ToUpper(); // Compliant
    }
}
```





# Los tipos de valor deberían implementar "IEquatable <T>"

Si está utilizando una estructura, es probable que esté interesado en el rendimiento.

```cs struct MyStruct  // Noncompliant
{
  private int i;
  public int I
  {
    //...
  }
}
```

```cs struct MyStruct : IEquatable<MyStruct>
{
  private int i;
  public int I
  {
    //...
  }

  public bool Equals(MyStruct other)
  {
    throw new NotImplementedException();
  }
}
```





# Los finalizadores no deben estar vacíos.

Los finalizadores vienen con un costo de rendimiento debido a la sobrecarga de seguimiento del ciclo de vida de los objetos.

```cs public class Foo
{
    ~Foo() // Noncompliant
    {
    }
}
```





# "[ExpectedException]" no debe utilizarse

Debe quedar claro para un lector casual qué código está probando una prueba y qué resultados se esperan.

Esta regla detecta los atributos MSTest y NUnit ExpectedException.

```cs [TestMethod]
[ExpectedException(typeof(ArgumentNullException))]  // Noncompliant
public void TestNullArg()
{
  //...
}
```

```cs [TestMethod]
public void TestNullArg()
{
  bool callFailed = false;
  try
  {
    //...
  }
  catch (ArgumentNullException)
  {
    callFailed = true;
  }
  Assert.IsTrue(callFailed, "Expected call to MyMethod to fail with ArgumentNullException");
}
```

Esta regla ignora los métodos de prueba de una línea, ya que es obvio en tales métodos donde se espera que se lance la excepción.





# "Esto" no debe ser expuesto por los constructores.

En entornos de un solo hilo, el uso de esto en constructores es normal y esperado.

El ejemplo clásico es una clase con una lista estática de sus instancias.

Esta regla plantea un problema cuando se asigna a cualquier objeto visible globalmente en un constructor, y cuando se pasa al método de otro objeto en un constructor

```cs public class Monument
{
  public static readonly List<Monument> ALL_MONUMENTS = new List<Monument>();
  // ...

  public Monument(string location, ...)
  {
    ALL_MONUMENTS.Add(this);  // Noncompliant; passed to a method of another object

    this.location = location;
    // ...
  }
}
```

Esta regla ignora las instancias de asignar esto directamente a un campo estático de la misma clase porque ese caso está cubierto por S3010.





# Los campos deben ser privados.

Los campos no deben formar parte de una API y, por lo tanto, siempre deben ser privados.

```cs public class Foo
{
  public int MagicNumber = 42;
}
```

```cs public class Foo
{
  public int MagicNumber
  {
    get { return 42; }
  }
}
```

Los campos no deben formar parte de una API y, por lo tanto, siempre deben ser privados.

```cs public class Foo
{
  private int MagicNumber = 42;
}
```

Los campos no deben formar parte de una API y, por lo tanto, siempre deben ser privados.

Además, solo se plantea un problema cuando la accesibilidad real es pública, teniendo en cuenta la accesibilidad de clase.





# NullReferenceException no debe ser capturado

NullReferenceException debe evitarse, no capturarse.

```cs public int GetLengthPlusTwo(string str)
{
    int length = 2;
    try
    {
       length += str.Length;
    }
    catch (NullReferenceException e)
    {
        log.info("argument was null");
    }
    return length;
}
```

```cs public int GetLengthPlusTwo(string str)
{
    int length = 2;

    if (str != null)
    {
        length += str.Length;
    }
    else
    {
        log.info("argument was null");
    }
    return length;
}
```





# Las funciones no deben tener demasiadas líneas de código.

Una función que crece demasiado tiende a agregar demasiadas responsabilidades.

Tales funciones inevitablemente se vuelven más difíciles de entender y, por lo tanto, más difíciles de mantener.

Por encima de un umbral específico, se recomienda enfáticamente refactorizar en funciones más pequeñas que se centren en tareas bien definidas.

Esas funciones más pequeñas no solo serán más fáciles de entender, sino también probablemente más fáciles de probar.





# "for" las condiciones de parada del bucle deben ser invariantes

Una condición de detención del bucle for debe probar el contador de bucles contra un valor invariante (es decir, uno que sea verdadero tanto al principio como al final de cada iteración del bucle).

Las condiciones de parada que no son invariantes son un poco menos eficientes, además de ser difíciles de entender y mantener, y probablemente conducen a la introducción de errores en el futuro.

Esta regla rastrea tres tipos de condiciones de parada no invariantes:

```cs class Foo
{
    static void Main()
    {
        for (int i = 1; i <= 5; i++)
        {
            Console.WriteLine(i);
            if (condition)
            {
               i = 20;
           }
        }
    }
}
```

```cs class Foo
{
    static void Main()
    {
        for (int i = 1; i <= 5; i++)
        {
            Console.WriteLine(i);
        }
    }
}
```





# Las declaraciones deben estar en líneas separadas

Para una mejor legibilidad, no coloque más de una declaración en una sola línea.

```cs if(someCondition) DoSomething();
```

```cs if(someCondition)
{
  DoSomething();
}
```

Las funciones anónimas que contienen una sola declaración se ignoran.

```cs Func<object, bool> item1 = o => { return true; }; // Compliant
Func<object, bool> item1 = o => { var r = false; return r; }; // Noncompliant
```





# Las clases no deben estar acopladas a demasiadas otras clases (Principio de Responsabilidad Única)

De acuerdo con el Principio de responsabilidad única, introducido por Robert C. Martin en su libro "Principios del diseño orientado a objetos", una clase debe tener una sola responsabilidad:

Si una clase tiene más de una responsabilidad, entonces las responsabilidades se juntan.

Los cambios en una responsabilidad pueden afectar o inhibir la capacidad de la clase para cumplir con las demás.

Este tipo de acoplamiento conduce a diseños frágiles que se rompen de manera inesperada cuando se cambian.

Las clases que dependen de muchas otras clases tienden a agregar demasiadas responsabilidades y deben dividirse en varias más pequeñas.

Las dependencias de clases anidadas no se cuentan como dependencias de la clase externa.

Con un umbral de 5:

```cs public class Foo    // Noncompliant - Foo depends on too many classes: T1, T2, T3, T4, T5, T6 and T7
{
  private T1 a1;    // Foo is coupled to T1
  private T2 a2;    // Foo is coupled to T2
  private T3 a3;    // Foo is coupled to T3

  public T4 Compute(T5 a, T6 b)    // Foo is coupled to T4, T5 and T6
  {
    T7 result = a.Process(b);    // Foo is coupled to T7
    return result;
  }

  public static class Bar    // Compliant - Bar depends on 2 classes: T8 and T9
  {
    public T8 a8;
    public T9 a9;
  }
}
```





# Las cláusulas de "cambio de caso" no deberían tener demasiadas líneas de código

La instrucción de cambio se debe usar solo para definir claramente algunas ramas nuevas en el flujo de control.

Con el umbral predeterminado de 3:

```cs switch (myVariable)
{
    case 0: // Noncompliant: 5 statements in the case
        methodCall1("");
        methodCall2("");
        methodCall3("");
        methodCall4("");
        break;
    case 1:
        ...
}
```

```cs switch (myVariable)
{
    case 0:
        DoSomething()
        break;
    case 1:
        ...
}
...
private void DoSomething()
{
    methodCall1("");
    methodCall2("");
    methodCall3("");
    methodCall4("");
}
```





# Con el umbral predeterminado de 3:

Un número mágico es un número que sale de la nada y se usa directamente en una declaración.

El uso de números mágicos puede parecer obvio y directo cuando se escribe un fragmento de código, pero son mucho menos obvios y directos en el momento de la depuración.

Es por eso que los números mágicos deben ser desmitificados al ser asignados primero a variables claramente nombradas antes de ser utilizados.

Es por eso que los números mágicos deben ser desmitificados al ser asignados primero a variables claramente nombradas antes de ser utilizados.

```cs public static void DoSomething()
{
    for(int i = 0; i < 4; i++)  // Noncompliant, 4 is a magic number
    {
        ...
    }
}
```

```cs private const int NUMBER_OF_CYCLES = 4;

public static void DoSomething()
{
    for(int i = 0; i < NUMBER_OF_CYCLES ; i++)  //Compliant
    {
        ...
    }
}
```

Esta regla no plantea un problema cuando el número mágico se usa como parte del método GetHashCode o una declaración de variable / campo.





# Las salidas estándar no deben usarse directamente para registrar nada

Al registrar un mensaje hay varios requisitos importantes que deben cumplirse:

Si un programa escribe directamente en las salidas estándar, no hay absolutamente ninguna manera de cumplir con esos requisitos.

```cs private void DoSomething()
{
    // ...
    Console.WriteLine("so far, so good..."); // Noncompliant
    // ...
}
```

Lo siguiente es ignorado por esta regla:





# Los archivos no deben tener demasiadas líneas de código

Un archivo fuente que crece demasiado tiende a agregar demasiadas responsabilidades y, inevitablemente, se vuelve más difícil de entender y, por lo tanto, de mantener.





# Las líneas no deben ser demasiado largas.

Tener que desplazarse horizontalmente hace que sea más difícil obtener una visión general rápida y la comprensión de cualquier pieza de código.





# No se debe utilizar el registro de la consola.

Las declaraciones de depuración siempre son útiles durante el desarrollo.

```cs private void DoSomething()
{
    // ...
    Console.WriteLine("so far, so good..."); // Noncompliant
    // ...
}
```

Lo siguiente es ignorado por esta regla:





# Los parámetros genéricos no restringidos a los tipos de referencia no deben compararse con "nulos"

Cuando no se han aplicado restricciones para restringir un parámetro de tipo genérico para que sea un tipo de referencia, entonces también se podría pasar un tipo de valor, como una estructura.

```cs private bool IsDefault<T>(T value)
{
  if (value == null) // Noncompliant
  {
    // ...
  }
  // ...
}
```

```cs private bool IsDefault<T>(T value)
{
  if(object.Equals(value, default(T)))
  {
    // ...
  }
  // ...
}
```

Cuando no se han aplicado restricciones para restringir un parámetro de tipo genérico para que sea un tipo de referencia, entonces también se podría pasar un tipo de valor, como una estructura.

```cs private bool IsDefault<T>(T value) where T : class
{
  if (value == null)
  {
    // ...
  }
  // ...
}
```





# Debe verificarse la longitud devuelta de una lectura de flujo

No puede asumir que cualquier llamada de lectura de secuencia completa llenará el byte [] pasado al método con el número de bytes solicitados.

Esta regla plantea un problema cuando se llama a un método Stream.Read o Stream.ReadAsync, pero el valor de retorno no se verifica.

```cs public void DoSomething(string fileName)
{
  using (var stream = File.Open(fileName, FileMode.Open))
  {
    var result = new byte[stream.Length];
    stream.Read(result, 0, (int)stream.Length); // Noncompliant
    // ... do something with result
  }
}
```

```cs public void DoSomething(string fileName)
{
  using (var stream = File.Open(fileName, FileMode.Open))
  {
    var buffer = new byte[1024];
    using (var ms = new MemoryStream())
    {
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            ms.Write(buffer, 0, read);
        }
        // ... do something with ms
    }
  }
}
```





# Los parámetros del método, las excepciones detectadas y los valores iniciales de las variables foreach no deben ignorarse

Si bien es técnicamente correcto asignar parámetros desde los cuerpos de los métodos, hacerlo antes de que se lea el valor del parámetro es probablemente un error.

```cs public void DoTheThing(string str, int i, List<string> strings)
{
  str = i.ToString(i);  // Noncompliant

  foreach (var s in strings)
  {
    s = "hello world";  // Noncompliant
  }
}
```





# Los métodos deben ser nombrados de acuerdo a sus sincronicidades.

De acuerdo con el Patrón asíncrono basado en tareas (TAP), los métodos que devuelven un System.Threading.Tasks.Task o un System.Threading.Tasks.Task <TResult> se consideran "asíncronos".

```cs using System;
using  System.Threading.Tasks;

namespace myLibrary
{

  public class Foo
  {
    public Task Read(byte [] buffer, int offset, int count, // Noncompliant
                                CancellationToken cancellationToken)
  }
}
```

```cs using System;
using  System.Threading.Tasks;

namespace myLibrary
{

  public class Foo
  {
    public Task ReadAsync(byte [] buffer, int offset, int count, CancellationToken cancellationToken)
  }
}
```

Esta regla no plantea un problema cuando el método es una anulación o parte de la implementación de una interfaz, ya que no se puede cambiar el nombre.





# Las extensiones deben estar en espacios de nombres separados

No tiene mucho sentido crear un método de extensión cuando es posible simplemente agregar ese método a la clase en sí.

Esta regla plantea un problema cuando una extensión se declara en el mismo espacio de nombres que la clase que extiende.

```cs namespace MyLibrary
{
    public class Foo
    {
        // ...
    }

    public static class MyExtensions
    {
        public static void Bar(this Foo a) // Noncompliant
        {
            // ...
        }
    }
}
```

Usando espacio de nombres separado:

```cs namespace MyLibrary
{
    public class Foo
    {
        // ...
    }
}

namespace Helpers
{
    public static class MyExtensions
    {
        public void Bar()
        {
            // ...
        }
    }
}
```

Fusionando el método en la clase:

```cs namespace MyLibrary
{
    public class Foo
    {
        // ...
        public void Bar()
        {
            // ...
        }
    }
}
```





# Los métodos de extensión no deben extender "objeto"

No se recomienda crear un método de extensión que extienda el objeto porque hace que el método esté disponible en todos los tipos.

```cs using System;

namespace MyLibrary
{
    public static class MyExtensions
    {
        public static void Foo(this object o)  //Noncompliant
        {
            // ...
        }
    }
}
```





# Sobrecargas del operador deben tener alternativas nombradas

La sobrecarga del operador es conveniente, pero desafortunadamente no es portátil en todos los idiomas.

Esta regla plantea un problema cuando hay una sobrecarga del operador sin el método alternativo con el nombre esperado.

Esta regla no plantea un problema cuando la clase que implementa los operadores de comparación>, <,> = y <= contiene un método llamado CompareTo.





# Debería usarse "params" en lugar de "varargs"

Un método que utiliza la convención de llamada de VarArgs no es compatible con la especificación de lenguaje común (CLS) y puede no ser accesible a través de lenguajes de programación, mientras que la palabra clave params funciona de la misma manera y es compatible con CLS.

Esta regla plantea un problema cuando un tipo público o protegido contiene un método público o protegido que usa la convención de llamadas VarArgs.

```cs using System;

namespace MyLibrary
{
    public class Foo
    {
        public void Bar(__arglist) // Noncompliant
        {
            ArgIterator argumentIterator = new ArgIterator(__arglist);
            for(int i = 0; i < argumentIterator.GetRemainingCount(); i++)
            {
                Console.WriteLine(
                    __refvalue(argumentIterator.GetNextArg(), string));
            }
        }
    }
}
```

```cs using System;

[assembly: CLSCompliant(true)]
namespace MyLibrary
{
    public class Foo
    {
        public void Bar(params string[] wordList)
        {
            for(int i = 0; i < wordList.Length; i++)
            {
                Console.WriteLine(wordList[i]);
            }
        }
    }
}
```

Los métodos de interoperabilidad que utilizan la convención de llamada VarArgs no plantean un problema.

```cs [DllImport("msvcrt40.dll")]
public static extern int printf(string format, __arglist); // Compliant
```





# Los atributos no abstractos deben ser sellados

La biblioteca de clases de .NET framework proporciona métodos para recuperar atributos personalizados.

Esta regla plantea un problema cuando un tipo público se hereda de System.Attribute, no es abstracto y no está sellado.

```cs using System;

namespace MyLibrary
{
    [AttributeUsage(AttributeTargets.Class|AttributeTargets.Struct)]
    public class MyAttribute: Attribute // Noncompliant
    {
        private string nameValue;
        public MyAttribute(string name)
        {
            nameValue = name;
        }

        public string Name
        {
            get
            {
                return nameValue;
            }
        }
    }
}
```

```cs using System;

namespace MyLibrary
{
    [AttributeUsage(AttributeTargets.Class|AttributeTargets.Struct)]
    public sealed class MyAttribute: Attribute
    {
        private string nameValue;
        public MyAttribute(string name)
        {
            nameValue = name;
        }

        public string Name
        {
            get
            {
                return nameValue;
            }
        }
    }
}
```





# Deben usarse sobrecargas con el parámetro "StringComparison"

Muchas operaciones de cadena, en particular los métodos Comparar e Igual, proporcionan una sobrecarga que acepta un valor de enumeración StringComparison como parámetro.

Esta regla plantea un problema cuando una operación de comparación de cadenas no usa la sobrecarga que toma un parámetro StringComparison.

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public bool HaveSameNames(string name1, string name2)
    {
      return string.Compare(name1, name2) == 0; // Noncompliant
    }
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public bool HaveSameNames(string name1, string name2)
    {
      return string.Compare(name1, name2, StringComparison.OrdinalIgnoreCase) == 0;
    }
  }
}
```





# Se deben utilizar sobrecargas con un parámetro "CultureInfo" o un parámetro "IFormatProvider"

Cuando no se proporciona un objeto System.Globalization.CultureInfo o IFormatProvider, el valor predeterminado que proporciona el miembro sobrecargado puede no tener el efecto que desea en todos los entornos locales.

Debe proporcionar información específica de la cultura de acuerdo con las siguientes pautas:

Esta regla plantea un problema cuando un método o constructor llama a uno o más miembros que tienen sobrecargas que aceptan un parámetro System.IFormatProvider, y el método o constructor no llama a la sobrecarga que toma el parámetro IFormatProvider.

```cs using System;

namespace MyLibrary
{
    public class Foo
    {
        public void Bar(String string1)
        {
            if(string.Compare(string1, string2, false) == 0) // Noncompliant
            {
                Console.WriteLine(string3.ToLower()); // Noncompliant
            }
        }
    }
}
```

```cs using System;
using System.Globalization;

namespace MyLibrary
{
    public class Foo
    {
        public void Bar(String string1, String string2, String string3)
        {
            if(string.Compare(string1, string2, false,
                              CultureInfo.InvariantCulture) == 0)
            {
                Console.WriteLine(string3.ToLower(CultureInfo.CurrentCulture));
            }
        }
    }
}
```

Esta regla no generará ningún problema cuando la sobrecarga se marque como obsoleta.





# Los tipos no deben extender los tipos de base obsoletos

Con el advenimiento de .NET framework versión 2, ciertas prácticas se han vuelto obsoletas.

En particular, las excepciones ahora deberían extender System.Exception en lugar de System.ApplicationException.

Esta regla plantea un problema cuando un tipo visible externamente extiende uno de estos tipos:

```cs using System;
using System.Collections;

namespace MyLibrary
{
  public class MyCollection : CollectionBase  // Noncompliant
  {
  }
}
```

```cs using System;
using System.Collections;

namespace MyLibrary
{
  public class MyCollection : Collection<T>
  {
  }
}
```





# Las propiedades deben ser preferidas

Se accede a las propiedades como campos que las hacen más fáciles de usar.

Esta regla plantea un problema cuando el nombre de un método público o protegido comienza con Obtener, no toma ningún parámetro y devuelve un valor que no es una matriz.

```cs using System;

namespace MyLibrary
{
    public class Foo
    {
        private string name;

        public string GetName()  // Noncompliant
        {
            return name;
        }
    }
}
```

```cs using System;

namespace MyLibrary
{
    public class Foo
    {
        private string name;

        public string Name
        {
            get
            {
                return name;
            }
        }
    }
}
```

La regla no plantea un problema cuando el método:





# Los genéricos deben usarse cuando sea apropiado

Cuando se usa un parámetro de referencia (referencia de palabra clave), el tipo de argumento pasado debe coincidir exactamente con el tipo de parámetro de referencia.

Esta regla plantea un problema cuando un método contiene un parámetro de referencia de tipo System.Object.

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public void Bar(ref object o1, ref object o2) // Noncompliant
    {
    }
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public void Bar<T>(ref T ref1, ref T ref2)
    {
    }
  }
}
```





# Los nombres de los tipos no deben coincidir con los espacios de nombres

Cuando un nombre de tipo coincide con el nombre de un espacio de nombres definido públicamente, por ejemplo, uno en la biblioteca de clases de .NET framework, genera confusión y hace que la biblioteca sea mucho más difícil de usar.

Esta regla plantea un problema cuando un nombre de un tipo público coincide con el nombre de un espacio de nombres de .NET Framework, o un espacio de nombres del conjunto del proyecto, en una comparación que no distingue entre mayúsculas y minúsculas.

```cs using System;

namespace MyLibrary
{
  public class Text   // Noncompliant: Collides with System.Text
  {
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class MyText
  {
  }
}
```





# Las cuerdas deben normalizarse a mayúsculas

Ciertos caracteres, una vez normalizados a minúsculas, no pueden realizar un viaje de ida y vuelta.

Por lo tanto, se recomienda encarecidamente normalizar los caracteres y las cadenas en mayúsculas.

```cs Thread.CurrentThread.CurrentCulture = new CultureInfo("tr-TR");
var areStringEqual = "INTEGER".ToLower() == "integer"; // Noncompliant, the result is false as the ToLower will resolve to "?nteger"
var areCharEqual = char.ToLower('I') == 'i'; // Noncompliant, the result is false as the ToLower will resolve to "?"

var incorrectRoundtrip = "?".ToLowerInvariant().ToUpper() == "I".ToLowerInvariant().ToUpper(); // Noncompliant, because of the lower we lose the information about the correct uppercase character
```

```cs Thread.CurrentThread.CurrentCulture = new CultureInfo("tr-TR");
var areStringEqual = "?nteger".ToUpperInvariant() == "?NTEGER";
var areCharEqual = char.ToUpperInvariant('?') == '?';
var correctRoundtrip = "?".ToUpperInvariant().ToLower() != "I".ToUpperInvariant().ToLower();
```





# Las excepciones deben proporcionar constructores estándar

Los tipos de excepciones deben proporcionar los siguientes constructores:

Ese cuarto constructor debe estar protegido en clases sin sellar, y privado en clases selladas.

No tener este conjunto completo de constructores puede dificultar el manejo de las excepciones.

```cs using System;

namespace MyLibrary
{
  public class MyException // Noncompliant: several constructors are missing
  {
    public MyException()
    {
    }
  }
}
```

```cs using System;
using System.Runtime.Serialization;

namespace MyLibrary
{
  public class MyException : Exception
  {
      public MyException()
      {
      }

      public MyException(string message)
          :base(message)
      {
      }

      public MyException(string message, Exception innerException)
          : base(message, innerException)
      {
      }

      protected MyException(SerializationInfo info, StreamingContext context)
          : base(info, context)
      {
      }
  }
}
```





# Los conjuntos deben estar marcados con "NeutralResourcesLanguageAttribute"

Es importante informar al ResourceManager del lenguaje utilizado para mostrar los recursos de la cultura neutral para un ensamblaje.

Esta regla plantea un problema cuando un ensamblaje contiene un recurso basado en ResX pero no tiene el System.Resources.NeutralResourcesLanguageAttribute aplicado a él.

```cs using System;

public class MyClass // Noncompliant
{
   public static void Main()
   {
      string[] cultures = { "de-DE", "en-us", "fr-FR" };
      Random rnd = new Random();
      int index = rnd.Next(0, cultures.Length);
      Thread.CurrentThread.CurrentUICulture = CultureInfo.CreateSpecificCulture(cultures[index]);

      ResourceManager rm = new ResourceManager("MyResources" ,
                                               typeof(MyClass).Assembly);
      string greeting = rm.GetString("Greeting");

      Console.Write("Enter your name: ");
      string name = Console.ReadLine();
      Console.WriteLine("{0} {1}!", greeting, name);
   }
}
```

```cs using System;

[assembly:NeutralResourcesLanguageAttribute("en")]
public class MyClass
{
   public static void Main()
   {
      string[] cultures = { "de-DE", "en-us", "fr-FR" };
      Random rnd = new Random();
      int index = rnd.Next(0, cultures.Length);
      Thread.CurrentThread.CurrentUICulture = CultureInfo.CreateSpecificCulture(cultures[index]);

      ResourceManager rm = new ResourceManager("MyResources" ,
                                               typeof(MyClass).Assembly);
      string greeting = rm.GetString("Greeting");

      Console.Write("Enter your name: ");
      string name = Console.ReadLine();
      Console.WriteLine("{0} {1}!", greeting, name);
   }
}
```





# Las interfaces no deben estar vacías

Las interfaces vacías se utilizan generalmente como un marcador o una forma de identificar grupos de tipos.

```cs using System;

namespace MyLibrary
{
   public interface MyInterface // Noncompliant
   {
   }
}
```

```cs using System;

namespace MyLibrary
{
   public interface MyInterface
   {
      void Foo();
   }
}
```





# Las enumeraciones deben tener almacenamiento "Int32"

Por defecto, el tipo de almacenamiento de una enumeración es Int32.

```cs using System;

namespace MyLibrary
{
    public enum Visibility : sbyte // Noncompliant
    {
        Visible = 0,
        Invisible = 1,
    }
}
```

```cs using System;

namespace MyLibrary
{
    public enum Visibility
    {
        Visible = 0,
        Invisible = 1,
    }
}
```





# Los métodos genéricos deben proporcionar parámetros de tipo

La mejor manera de determinar el tipo de un método genérico es por inferencia en función del tipo de argumento que se pasa al método.

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public void MyMethod<T>()  // Noncompliant
    {
    }
  }
}
```

```cs using System;

namespace MyLibrary
{
  public class Foo
  {
    public void MyMethod<T>(T param)
    {
    }
  }
}
```





# No se deben usar matrices multidimensionales.

Una matriz dentada es una matriz cuyos elementos son matrices.

```cs int [,] myArray =  // Noncompliant
    {
        {1,2,3,4},
        {5,6,7,0},
        {8,0,0,0},
        {9,0,0,0}
    };
// ...
myArray[1,1] = 0;
```

```cs int[][] myArray =
    {
        new int[] {1,2,3,4},
        new int[] {5,6,7},
        new int[] {8},
        new int[] {9}
    };
// ...
myArray[1][1] = 0;
```





# Las constantes "readonly estáticas" deberían ser "const" en su lugar

El valor de un campo de lectura estática solo se calcula en tiempo de ejecución, mientras que el valor de un campo constante se calcula en tiempo de compilación, lo que mejora el rendimiento.

Esta regla plantea un problema cuando un campo de solo lectura estática se inicializa con un valor que se puede calcular en el momento de la compilación.

Según lo especificado por Microsoft, la lista de tipos que pueden tener un valor constante son:

```cs namespace myLib
{
  public class Foo
  {
    static readonly int x = 1;  // Noncompliant
    static readonly int y = x + 4; // Noncompliant
    static readonly string s = "Bar";  // Noncompliant
  }
}
```

```cs namespace myLib
{
  public class Foo
  {
    const int x = 1;
    const int y = x + 4;
    const string s = "Bar";
  }
}
```





# Deben utilizarse cadenas o tipos integrales para los indexadores.

Las cadenas y los tipos integrales se utilizan normalmente como indexadores.

```cs public int this[MyCustomClass index]  // Noncompliant
{
    // get and set accessors
}
```





# Los nombres de los parámetros no deben duplicar los nombres de sus métodos.

El nombre de un método debe comunicar lo que hace, y los nombres de sus parámetros deben indicar cómo se usan.

```cs public void Login(string login)  // Noncompliant
{
  //...
}
```

```cs public void Login(string userName)
{
  //...
}
```





# Seguimiento del uso de "NotImplementedException"

NotImplementedException se usa a menudo para marcar métodos que deben implementarse para que la funcionalidad general esté completa, pero que el desarrollador desea implementar más adelante.

Esta regla genera una excepción cuando se emite NotImplementedException.

```cs void doTheThing()
{
    throw new NotImplementedException();
}
```

Las excepciones derivadas de NotImplementedException se ignoran.





# Se deben eliminar las cláusulas "predeterminadas" vacías

La cláusula por defecto debe tomar la acción apropiada.

```cs enum Fruit
{
  Apple,
  Orange,
  Banana
}

void PrintName(Fruit fruit)
{
  switch(fruit)
  {
    case Fruit.Apple:
      Console.WriteLine("apple");
      break;
    default:  //Noncompliant
      break;
  }
}
```

```cs enum Fruit
{
  Apple,
  Orange,
  Banana
}

void PrintName(Fruit fruit)
{
  switch(fruit)
  {
    case Fruit.Apple:
      Console.WriteLine("apple");
      break;
    default:
      throw new NotSupportedException();
  }
}
```

La cláusula por defecto debe tomar la acción apropiada.

```cs void PrintName(Fruit fruit)
{
  switch(fruit)
  {
    case Fruit.Apple:
      Console.WriteLine("apple");
      break;
  }
}
```

La cláusula por defecto debe tomar la acción apropiada.





# Los nombres de propiedad redundantes deben omitirse en clases anónimas

Cuando las propiedades de un tipo anónimo se copian de propiedades o variables con los mismos nombres, se obtiene un código más limpio para omitir el nuevo nombre de propiedad de tipo y el operador de asignación.

```cs var X = 5;

var anon = new
{
  X = X, //Noncompliant, the new object would have the same property without the "X =" part.
  Y = "my string"
};
```

```cs var X = 5;

var anon = new
{
  X,
  Y = "my string"
};
```





# Las declaraciones y las inicializaciones deben ser lo más concisas posible.

Las declaraciones e inicializaciones innecesariamente detalladas hacen que sea más difícil leer el código, y deben simplificarse.

Específicamente, se debe omitir lo siguiente cuando pueden inferirse:

```cs var l = new List<int>() {}; // Noncompliant, {} can be removed
var o = new object() {}; // Noncompliant, {} can be removed

var ints = new int[] {1, 2, 3}; // Noncompliant, int can be omitted
ints = new int[3] {1, 2, 3}; // Noncompliant, the size specification can be removed

int? i = new int?(5); // Noncompliant new int? could be omitted, it can be inferred from the declaration, and there's implicit conversion from T to T?
var j = new int?(5);

Func<int, int> f1 = (int i) => 1; //Noncompliant, can be simplified

class Class
{
    private event EventHandler MyEvent;

    public Class()
    {
        MyEvent += new EventHandler((a,b)=>{ }); // Noncompliant, needlessly verbose
    }
}
```

```cs var l = new List<int>();
var o = new object();

var ints = new [] {1, 2, 3};
ints = new [] {1, 2, 3};

int? i = 5;
var j = new int?(5);

Func<int, int> f1 = (i) => 1;

class Class
{
    private event EventHandler MyEvent;

    public Class()
    {
        MyEvent += (a,b)=>{ };
    }
}
```





# Los valores predeterminados de los parámetros no deben pasarse como argumentos

La especificación de los valores de parámetros predeterminados en una llamada de método es redundante.

```cs public void M(int x, int y=5, int z = 7) { /* ... */ }

// ...
M(1, 5); //Noncompliant, y has the default value
M(1, z: 7); //Noncompliant, z has the default value
```

```cs public void M(int x, int y=5, int z = 7) { /* ... */ }

// ...
M(1);
M(1);
```





# Las declaraciones de constructor y destructor no deben ser redundantes

Dado que el compilador invocará automáticamente el constructor sin argumentos del tipo base, no es necesario especificar explícitamente su invocación.

```cs class X
{
  public X() { } // Noncompliant
  static X() { }  // Noncompliant
  ~X() { } // Noncompliant

  ...
}

class Y : X
{
  public Y(int parameter) : base() // Noncompliant
  {
    /* does something with the parameter */
  }
}
```

```cs class X
{
  ...
}

class Y : X
{
  public Y(int parameter)
  {
    /* does something with the parameter */
  }
}
```





# Los parámetros del método deben ser declarados con tipos base.

Cuando se usa un tipo derivado como parámetro en lugar del tipo base, limita los usos del método.

Esta regla plantea un problema cuando una declaración de método incluye un parámetro que es un tipo derivado y accede solo a los miembros del tipo base.

```cs using System;
using System.IO;

namespace MyLibrary
{
  public class Foo
  {
    public void ReadStream(FileStream stream) // Noncompliant: Uses only System.IO.Stream methods
    {
      int a;
      while ((a = stream.ReadByte()) != -1)
      {
            // Do something.
      }
    }
  }
}
```

```cs using System;
using System.IO;

namespace MyLibrary
{
  public class Foo
  {
    public void ReadStream(Stream stream)
    {
      int a;
      while ((a = stream.ReadByte()) != -1)
      {
            // Do something.
      }
    }
  }
}
```





# Debe utilizarse la sintaxis de condición más simple posible.

Con el fin de mantener limpio el código, se debe utilizar la sintaxis condicional más simple posible.

```cs object a = null, b = null, x;

if (a != null) // Noncompliant; needlessly verbose
{
  x = a;
}
else
{
  x = b;
}

x = a != null ? a : b; // Noncompliant; better but could still be simplified

x = (a == null) ? new object() : a; // Noncompliant

if (condition) // Noncompliant
{
  x = a;
}
else
{
  x = b;
}

var y = null ?? new object(); // Noncompliant
```

```cs object x;

x = a ?? b;
x = a ?? b;
x = a ?? new object();
x = condition ? a : b;
var y = new object();
```





# No se deben utilizar paréntesis redundantes.

Los paréntesis redundantes son simplemente pulsaciones de teclas desperdiciadas, y deben eliminarse.

```cs [MyAttribute()] //Noncompliant
class MyClass
{
  public int MyProperty { get; set; }
  public static MyClass CreateNew(int propertyValue)
  {
    return new MyClass() //Noncompliant
    {
      MyProperty = propertyValue
    };
  }
}
```

```cs [MyAttribute]
class MyClass
{
  public int MyProperty { get; set; }
  public static MyClass CreateNew(int propertyValue)
  {
    return new MyClass
    {
      MyProperty = propertyValue
    };
  }
}
```





# "GC.SuppressFinalize" no debe invocarse para tipos sin destructores

GC.SuppressFinalize le pide al Common Language Runtime que no llame al finalizador de un objeto.

Esta regla plantea un problema cuando se llama a GC.SuppressFinalize para objetos de tipos sellados sin un finalizador.

Nota: ** {rule: csharpsquid: S3971} es una versión más estricta de esta regla.

```cs sealed class MyClass
{
  public void Method()
  {
    ...
    GC.SuppressFinalize(this); //Noncompliant
  }
}
```

```cs sealed class MyClass
{
  public void Method()
  {
    ...
  }
}
```





# Los miembros no deben inicializarse a valores predeterminados

El compilador inicializa automáticamente los campos de clase, las propiedades automáticas y los eventos a sus valores predeterminados antes de establecerlos con cualquier valor de inicialización, por lo que no es necesario establecer explícitamente un miembro a su valor predeterminado.

```cs class X
{
  public int field = 0; // Noncompliant
  public object o = null; // Noncompliant
  public object MyProperty { get; set; } = null; // Noncompliant
  public event EventHandler MyEvent = null;  // Noncompliant
}
```

```cs class X
{
  public int field;
  public object o;
  public object MyProperty { get; set; }
  public event EventHandler MyEvent;
}
```

El compilador inicializa automáticamente los campos de clase, las propiedades automáticas y los eventos a sus valores predeterminados antes de establecerlos con cualquier valor de inicialización, por lo que no es necesario establecer explícitamente un miembro a su valor predeterminado.





# Las pruebas secuenciales no deben comprobar la misma condición

Cuando se verifica la misma condición dos veces seguidas, es confuso: ¿por qué tener cheques separados?

```cs if (a == b)
{
  doTheThing(b);
}
if (a == b) // Noncompliant; is this really what was intended?
{
  doTheThing(c);
}
```

```cs if (a == b)
{
  doTheThing(b);
  doTheThing(c);
}
```

Cuando se verifica la misma condición dos veces seguidas, es confuso: ¿por qué tener cheques separados?

```cs if (a == b)
{
  doTheThing(b);
}
if (b == c)
{
  doTheThing(c);
}
```

Ya que es un patrón común probar una variable, reasignarla si falla la prueba, luego volver a probarla, ese patrón se ignora.





# No se deben utilizar modificadores redundantes.

Las palabras clave innecesarias simplemente saturan el código y deben eliminarse.

```cs public partial class MyClass // Noncompliant
{
  public virtual void Method()
  {
  }
}

public sealed class MyOtherClass : MyClass
{
  public sealed override void Method() // Noncompliant
  {
  }
}
```

```cs public class MyClass
{
  public virtual void Method()
  {
  }
}

public sealed class MyOtherClass : MyClass
{
  public override void Method()
  {
  }
}
```





# Los métodos y propiedades que no acceden a los datos de instancia deben ser estáticos

Los métodos de clase y las propiedades que no acceden a los datos de instancia pueden ser estáticos para evitar cualquier malentendido sobre el contrato del método.

```cs public class Utilities
{
  public int MagicNum // Noncompliant
  {
    get
    {
      return 42;
    }
  }

  private static string magicWord = "please";
  public string MagicWord  // Noncompliant
  {
    get
    {
      return magicWord;
    }
    set
    {
      magicWord = value;
    }
  }

  public int Sum(int a, int b)  // Noncompliant
  {
    return a + b;
  }
}
```

```cs public class Utilities
{
  public static int MagicNum
  {
    get
    {
      return 42;
    }
  }

  private static string magicWord = "please";
  public static string MagicWord
  {
    get
    {
      return magicWord;
    }
    set
    {
      magicWord = value;
    }
  }

  public static int Sum(int a, int b)
  {
    return a + b;
  }
}
```





# La "excepción" no debe capturarse cuando no sea requerida por los métodos llamados

La captura de System.Exception parece ser una forma eficiente de manejar múltiples excepciones posibles.

```cs try
{
  // do something that might throw a FileNotFoundException or IOException
}
catch (Exception e) // Noncompliant
{
  // log exception ...
}
```

```cs try
{
  // do something
}
catch (Exception e) when (e is FileNotFoundException || e is IOException)
{
  // do something
}
```

La opción final es capturar System.Exception y lanzarlo en la última instrucción del bloque catch.

```cs try
{
  // do something
}
catch (Exception e)
{
  if (e is FileNotFoundException || e is IOException)
  {
    // do something
  }
  else
  {
    throw;
  }
}
```





# Las clases "selladas" no deben tener miembros "protegidos"

La diferencia entre visibilidad privada y protegida es que las clases secundarias pueden ver y usar miembros protegidos, pero no pueden ver clases privadas.

```cs public sealed class MySealedClass
{
    protected string name = "Fred";  // Noncompliant
    protected void SetName(string name) // Noncompliant
    {
        // ...
    }
}
```

```cs public sealed class MySealedClass
{
    private string name = "Fred";
    public void SetName(string name)
    {
        // ...
    }
}
```





# Deben usarse guiones bajos para hacer que los números grandes sean legibles

A partir de C # 7, es posible agregar guiones bajos ('_') a literales numéricos para mejorar la legibilidad.

El número de dígitos a la izquierda de un punto decimal necesario para activar esta regla varía según la base.

Es solo la presencia de guiones bajos, no su espacio lo que se analiza con esta regla.

Tenga en cuenta que esta regla se desactiva automáticamente cuando la versión C # del proyecto es inferior a 7.

```cs int i = 10000000;  // Noncompliant; is this 10 million or 100 million?
int  j = 0b01101001010011011110010101011110;  // Noncompliant
long l = 0x7fffffffffffffffL;  // Noncompliant
```

```cs int i = 10_000_000;
int  j = 0b01101001_01001101_11100101_01011110;
long l = 0x7fff_ffff_ffff_ffffL;
```





# Las llamadas "ToString ()" no deben ser redundantes

Invocar un método diseñado para devolver una representación de cadena de un objeto que ya es una cadena es un desperdicio de pulsaciones de teclas.

Esta regla plantea un problema cuando se invoca ToString ():

```cs var s = "foo";
var t = "fee fie foe " + s.ToString();  // Noncompliant
var someObject = new object();
var u = "" + someObject.ToString(); // Noncompliant
var v = string.Format("{0}", someObject.ToString()); // Noncompliant
```

```cs var s = "foo";
var t = "fee fie foe " + s;
var someObject = new object();
var u = "" + someObject;
var v = string.Format("{0}", someObject);
```

La regla no informa sobre los tipos de valor, donde dejar de realizar la llamada ToString () resultaría en un boxeo automático.

```cs var v = string.Format("{0}", 1.ToString());
```





# "==" no debe usarse cuando "Igual a" está anulado

El uso de los operadores de igualdad == y desigualdad! = Para comparar dos objetos generalmente funciona.

```cs public interface IMyInterface
{
}

public class MyClass : IMyInterface
{
    public override bool Equals(object obj)
    {
        //...
    }
}

public class Program
{
    public static void Method(IMyInterface instance1, IMyInterface instance2)
    {
        if (instance1 == instance2) // Noncompliant, will do reference equality check, but was that intended? MyClass overrides Equals.
        {
            Console.WriteLine("Equal");
        }
    }
}
```

```cs public interface IMyInterface
{
}

public class MyClass : IMyInterface
{
    public override bool Equals(object obj)
    {
        //...
    }
}

public class Program
{
    public static void Method(IMyInterface instance1, IMyInterface instance2)
    {
        if (object.Equals(instance1, instance2)) // object.Equals checks for null and then calls the instance based Equals, so MyClass.Equals
        {
            Console.WriteLine("Equal");
        }
    }
}
```

La regla no informa sobre comparaciones de instancias de System.Type y sobre comparaciones dentro de sustituciones de Equals.

Tampoco plantea un problema cuando uno de los operandos es nulo ni cuando uno de los operandos se convierte en objeto (porque en este caso queremos asegurar la igualdad de referencia incluso si existe una sobrecarga ==).





# Una clase abstracta debe tener métodos abstractos y concretos.

El propósito de una clase abstracta es proporcionar algunos comportamientos hereditarios y, al mismo tiempo, definir métodos que deben ser implementados por subclases.

Una clase sin métodos abstractos que se hizo abstracta únicamente para evitar la creación de instancias debería convertirse en una clase concreta (es decir, eliminar la palabra clave abstracta) con un constructor protegido.

Una clase con solo métodos abstractos y sin comportamiento heredable debe convertirse a una interfaz.

```cs public abstract class Animal //Noncompliant; should be an interface
{
  abstract void Move();
  abstract void Feed();
}

public abstract class Color //Noncompliant; should be concrete with a private constructor
{
  private int red = 0;
  private int green = 0;
  private int blue = 0;

  public int GetRed()
  {
    return red;
  }
}
```

```cs public interface Animal
{
  void Move();
  void Feed();
}

public class Color
{
  private int red = 0;
  private int green = 0;
  private int blue = 0;

  protected Color()
  {}

  public int GetRed()
  {
    return red;
  }
}

public abstract class Lamp
{
  private bool switchLamp = false;

  public abstract void Glow();

  public void FlipSwitch()
  {
    switchLamp = !switchLamp;
    if (switchLamp)
    {
      Glow();
    }
  }
}
```





# Las variables múltiples no deben ser declaradas en la misma línea

Declarar múltiples variables en una línea es difícil de leer.

```cs class MyClass
{
  private int a, b; // Noncompliant

  public void Method()
  {
    int c, d; // Noncompliant
  }
}
```

```cs class MyClass
{
  private int a;
  private int b;

  public void Method()
  {
    int c;
    int d;
  }
}
```





# La cultura debe especificarse para las operaciones de "cadena"

La cultura debe especificarse para las operaciones de "cadena"

La cultura debe especificarse para las operaciones de "cadena"

Las llamadas sin una cultura pueden funcionar bien en el entorno "doméstico" del sistema, pero se rompen en formas que son extremadamente difíciles de diagnosticar para los clientes que utilizan diferentes codificaciones.

```cs var lowered = someString.ToLower(); //Noncompliant
```

```cs var lowered = someString.ToLower(CultureInfo.InvariantCulture);
```

Las llamadas sin una cultura pueden funcionar bien en el entorno "doméstico" del sistema, pero se rompen en formas que son extremadamente difíciles de diagnosticar para los clientes que utilizan diferentes codificaciones.

```cs var lowered = someString.ToLowerInvariant();
```





# Las declaraciones de "cambio" deben tener al menos 3 cláusulas de "caso"

Las declaraciones de "cambio" deben tener al menos 3 cláusulas de "caso"

Sin embargo, solo para uno o dos casos, el código será más legible con las instrucciones if.

```cs switch (variable)
{
  case 0:
    doSomething();
    break;
  default:
    doSomethingElse();
    break;
}
```

```cs if (variable == 0)
{
  doSomething();
}
else
{
  doSomethingElse();
}
```





# Sin embargo, solo para uno o dos casos, el código será más legible con las instrucciones if.

Sin embargo, solo para uno o dos casos, el código será más legible con las instrucciones if.

Idealmente, cada bucle debería tener una condición de terminación única.

```cs int i = 0;
while (true)
{
  if (i == 10)
  {
    break;      // Non-Compliant
  }

  Console.WriteLine(i);
  i++;
}
```

```cs int i = 0;
while (i != 10) // Compliant
{
  Console.WriteLine(i);
  i++;
}
```





# Los literales de cadena no deben ser duplicados.

Los literales de cadena duplicados hacen que el proceso de refactorización sea propenso a errores, ya que debe asegurarse de actualizar todas las incidencias.

Por otro lado, las constantes pueden ser referenciadas desde muchos lugares, pero solo necesitan actualizarse en un solo lugar.

```cs public class Foo
{
    private string name = "foobar"; // Noncompliant

    public string DefaultName { get; } = "foobar"; // Noncompliant

    public Foo(string value = "foobar") // Noncompliant
    {
        var something = value ?? "foobar"; // Noncompliant
    }
}
```

```cs public class Foo
{
    private const string Foobar = "foobar";

    private string name = Foobar;

    public string DefaultName { get; } = Foobar;

    public Foo(string value = Foobar)
    {
        var something = value ?? Foobar;
    }
}
```

Se ignoran los siguientes:





# Los archivos deben contener una nueva línea vacía al final

Algunas herramientas funcionan mejor cuando los archivos terminan con una línea vacía.

Esta regla simplemente genera un problema si falta.

Por ejemplo, un Git diff tiene este aspecto si falta una línea al final del archivo:

```cs +class Test
+{
+}
\ No newline at end of file
```





# Un corchete cerrado debe estar ubicado al comienzo de una línea

Las convenciones de codificación compartidas hacen posible que un equipo colabore de manera eficiente.

```cs if(condition)
{
  doSomething();}
```

```cs if(condition)
{
  doSomething();
}
```

Cuando los bloques están en línea (abre y cierra llaves en la misma línea), no se activa ningún problema.

```cs if(condition) {doSomething();}
```





# No se deben utilizar caracteres de tabulación.

Los desarrolladores no deberían necesitar configurar el ancho de la pestaña de sus editores de texto para poder leer el código fuente.

Por lo tanto, el uso del carácter de tabulación debe ser prohibido.





# Métodos y propiedades deben ser nombrados en PascalCase

Las convenciones de nomenclatura compartidas permiten que los equipos colaboren de manera eficiente.

```cs public int doSomething(){...}
```

```cs public int DoSomething(){...}
```

La regla ignora a los miembros en los tipos que están marcados con ComImportAttribute o InterfaceTypeAttribute.

```cs void My_method(){...} // valid
void My_method_(){...} // invalid, leading and trailing underscores are reported
```





# Rastrear usos de supresiones de problemas en la fuente

Esta regla le permite rastrear el uso de los atributos SuppressMessage y el mecanismo de desactivación de la advertencia #pragma.

```cs [SuppressMessage("", "S100")]
...

#pragma warning disable S100
...
#pragma warning restore S100
```



