using System;
using System.ServiceModel;
using ClienteConsola.ServiceReference1;

namespace ClienteConsola
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "Cliente WCF - BancoABC";

            while (true)
            {
                Console.Clear();
                Console.WriteLine("╔════════════════════════════════╗");
                Console.WriteLine("║   BANCOABC - SISTEMA WCF      ║");
                Console.WriteLine("╚════════════════════════════════╝");
                Console.WriteLine();
                Console.WriteLine("1. Registrar nuevo usuario");
                Console.WriteLine("2. Iniciar sesión");
                Console.WriteLine("3. Salir");
                Console.Write("Opción: ");

                string opcion = Console.ReadLine();

                switch (opcion)
                {
                    case "1":
                        RegistrarUsuario();
                        break;
                    case "2":
                        IniciarSesion();
                        break;
                    case "3":
                        return;
                }
            }
        }

        static void RegistrarUsuario()
        {
            try
            {
                Console.Clear();
                Console.WriteLine("=== REGISTRO DE NUEVO USUARIO ===\n");

                var cliente = new ServiceReference1.ServicioAutenticacionClient();

                Console.Write("Identificación: ");
                string id = Console.ReadLine();

                Console.Write("Nombre: ");
                string nombre = Console.ReadLine();

                Console.Write("Primer Apellido: ");
                string apellido1 = Console.ReadLine();

                Console.Write("Segundo Apellido: ");
                string apellido2 = Console.ReadLine();

                Console.Write("Email: ");
                string email = Console.ReadLine();

                Console.Write("Usuario: ");
                string usuario = Console.ReadLine();

                Console.Write("Contraseña: ");
                string contrasena = Console.ReadLine();

                Console.Write("Tipo (1=Empleado, 2=Cliente): ");
                int tipo = int.Parse(Console.ReadLine());

                var nuevoUsuario = new ServiceReference1.UsuarioRegistro
                {
                    Identificacion = id,
                    Nombre = nombre,
                    PrimerApellido = apellido1,
                    SegundoApellido = apellido2,
                    Email = email,
                    Usuario = usuario,
                    Contrasena = contrasena,
                    Tipo = tipo
                };

                Console.WriteLine("\nRegistrando usuario...");
                var resultado = cliente.RegistrarUsuario(nuevoUsuario);

                if (resultado.Exitoso)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n✅ " + resultado.Mensaje);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n❌ " + resultado.Mensaje);
                }
                Console.ResetColor();

                cliente.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n❌ Error: " + ex.Message);
            }

            Console.WriteLine("\nPresione una tecla para continuar...");
            Console.ReadKey();
        }

        static void IniciarSesion()
        {
            try
            {
                Console.Clear();
                Console.WriteLine("=== INICIAR SESIÓN ===\n");

                var cliente = new ServiceReference1.ServicioAutenticacionClient();

                Console.Write("Usuario: ");
                string usuario = Console.ReadLine();

                Console.Write("Contraseña: ");
                string contrasena = Console.ReadLine();

                string usuarioEnc = Encriptacion.Encriptar(usuario);
                string passEnc = Encriptacion.Encriptar(contrasena);

                var credenciales = new ServiceReference1.Credenciales
                {
                    UsuarioEncriptado = usuarioEnc,
                    ContrasenaEncriptada = passEnc
                };

                Console.WriteLine("\nValidando credenciales...");
                var resultado = cliente.ValidarLogin(credenciales);

                Console.WriteLine("\n=== RESULTADO ===");
                if (resultado.Resultado)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✅ " + resultado.Mensaje);

                    string tipo = resultado.TipoUsuario == 1 ? "EMPLEADO" : "CLIENTE";
                    Console.WriteLine("👤 Tipo: " + tipo);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ " + resultado.Mensaje);
                }
                Console.ResetColor();

                cliente.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n❌ Error: " + ex.Message);
            }

            Console.WriteLine("\nPresione una tecla para continuar...");
            Console.ReadKey();
        }
    }
}