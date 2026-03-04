using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ServiceModel;
using System.ServiceModel.Activation;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Configuration;
using System.Diagnostics;

/// <summary>
/// Implementación del servicio de autenticación
/// </summary>
[AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
public class ServicioAutenticacion : IServicioAutenticacion
{
    private IMongoCollection<UsuarioMongo> _coleccionUsuarios;

    public ServicioAutenticacion()
    {
        try
        {
            // Configurar conexión a MongoDB
            string connectionString = ConfigurationManager.AppSettings["MongoDBConnection"] ?? "mongodb://localhost:27017";
            string databaseName = ConfigurationManager.AppSettings["MongoDBDatabase"] ?? "BancoABC";
            string collectionName = ConfigurationManager.AppSettings["MongoDBCollection"] ?? "Usuarios";

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase(databaseName);
            _coleccionUsuarios = database.GetCollection<UsuarioMongo>(collectionName);

            Debug.WriteLine("[Servicio] Conectado a MongoDB correctamente");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("[Servicio] Error conectando a MongoDB: " + ex.Message);
        }
    }

    public ResultadoAutenticacion ValidarLogin(Credenciales credenciales)
    {
        var resultado = new ResultadoAutenticacion();

        try
        {
            // Validar que las credenciales no sean nulas
            if (credenciales == null ||
                string.IsNullOrEmpty(credenciales.UsuarioEncriptado) ||
                string.IsNullOrEmpty(credenciales.ContrasenaEncriptada))
            {
                resultado.Resultado = false;
                resultado.Mensaje = "Credenciales no proporcionadas";
                return resultado;
            }

            // Desencriptar credenciales recibidas
            string usuario = Encriptacion.Desencriptar(credenciales.UsuarioEncriptado);
            string contrasena = Encriptacion.Desencriptar(credenciales.ContrasenaEncriptada);

            Debug.WriteLine("[Servicio] Validando login para usuario (desencriptado): " + usuario);

            // ✅ ENCRIPTAR EL USUARIO PARA BUSCARLO EN LA BD
            string usuarioEncriptado = Encriptacion.Encriptar(usuario);
            Debug.WriteLine("[Servicio] Buscando usuario encriptado: " + usuarioEncriptado);

            // ✅ Buscar usuario en MongoDB por usuario ENCRIPTADO
            var filter = Builders<UsuarioMongo>.Filter.Eq(u => u.Usuario, usuarioEncriptado);
            var usuarioEncontrado = _coleccionUsuarios.Find(filter).FirstOrDefault();

            // Verificar si el usuario existe
            if (usuarioEncontrado == null)
            {
                Debug.WriteLine("[Servicio] Usuario no encontrado en BD");
                resultado.Resultado = false;
                resultado.Mensaje = "Usuario y/o contraseña incorrectos";
                return resultado;
            }

            // Desencriptar la contraseña almacenada
            string contrasenaAlmacenada = Encriptacion.Desencriptar(usuarioEncontrado.Contrasena);

            Debug.WriteLine("[Servicio] Contraseña ingresada: " + contrasena);
            Debug.WriteLine("[Servicio] Contraseña almacenada (desencriptada): " + contrasenaAlmacenada);

            // Verificar contraseña y estado
            if (contrasenaAlmacenada == contrasena)
            {
                if (usuarioEncontrado.Estado.ToLower() == "activo")
                {
                    resultado.Resultado = true;
                    resultado.Mensaje = "Exitoso";
                    resultado.TipoUsuario = usuarioEncontrado.Tipo;

                    Debug.WriteLine("[Servicio] Login exitoso para usuario");
                }
                else
                {
                    resultado.Resultado = false;
                    resultado.Mensaje = "Usuario inactivo";
                }
            }
            else
            {
                resultado.Resultado = false;
                resultado.Mensaje = "Usuario y/o contraseña incorrectos";
            }
        }
        catch (Exception ex)
        {
            resultado.Resultado = false;
            resultado.Mensaje = "Error en el servicio";
            Debug.WriteLine("[Servicio] Error en ValidarLogin: " + ex.Message);
        }

        return resultado;
    }

    public ResultadoRegistro RegistrarUsuario(UsuarioRegistro usuario)
    {
        var resultado = new ResultadoRegistro();

        try
        {
            Debug.WriteLine("[Servicio] Intentando registrar usuario: " + usuario.Usuario);

            // Validar campos obligatorios
            if (string.IsNullOrEmpty(usuario.Usuario) || string.IsNullOrEmpty(usuario.Contrasena))
            {
                resultado.Exitoso = false;
                resultado.Mensaje = "Usuario y contraseña son obligatorios";
                return resultado;
            }

            // ✅ ENCRIPTAR EL USUARIO Y LA CONTRASEÑA ANTES DE GUARDAR
            string usuarioEncriptado = Encriptacion.Encriptar(usuario.Usuario);
            string contrasenaEncriptada = Encriptacion.Encriptar(usuario.Contrasena);

            Debug.WriteLine("[Servicio] Usuario original: " + usuario.Usuario);
            Debug.WriteLine("[Servicio] Usuario encriptado: " + usuarioEncriptado);
            Debug.WriteLine("[Servicio] Contraseña encriptada: " + contrasenaEncriptada);

            // ✅ Validar que el usuario (encriptado) no exista
            var filter = Builders<UsuarioMongo>.Filter.Eq(u => u.Usuario, usuarioEncriptado);
            var existe = _coleccionUsuarios.Find(filter).Any();

            if (existe)
            {
                resultado.Exitoso = false;
                resultado.Mensaje = "El nombre de usuario ya existe";
                return resultado;
            }

            // Validar que el email no exista (el email NO se encripta para poder buscarlo)
            if (!string.IsNullOrEmpty(usuario.Email))
            {
                filter = Builders<UsuarioMongo>.Filter.Eq(u => u.Email, usuario.Email);
                existe = _coleccionUsuarios.Find(filter).Any();

                if (existe)
                {
                    resultado.Exitoso = false;
                    resultado.Mensaje = "El email ya está registrado";
                    return resultado;
                }
            }

            // ✅ Crear el documento para MongoDB con USUARIO Y CONTRASEÑA ENCRIPTADOS
            var nuevoUsuario = new UsuarioMongo
            {
                Identificacion = usuario.Identificacion ?? "",
                Nombre = usuario.Nombre ?? "",
                PrimerApellido = usuario.PrimerApellido ?? "",
                SegundoApellido = usuario.SegundoApellido ?? "",
                Email = usuario.Email ?? "",
                Usuario = usuarioEncriptado,        // ✅ USUARIO ENCRIPTADO
                Contrasena = contrasenaEncriptada,  // ✅ CONTRASEÑA ENCRIPTADA
                Estado = "activo",
                Tipo = usuario.Tipo
            };

            // Guardar en MongoDB
            _coleccionUsuarios.InsertOne(nuevoUsuario);

            Debug.WriteLine("[Servicio] Usuario registrado exitosamente");

            resultado.Exitoso = true;
            resultado.Mensaje = "Usuario registrado exitosamente";
        }
        catch (Exception ex)
        {
            Debug.WriteLine("[Servicio] Error registrando usuario: " + ex.Message);
            resultado.Exitoso = false;
            resultado.Mensaje = "Error en el servicio: " + ex.Message;
        }

        return resultado;
    }
}