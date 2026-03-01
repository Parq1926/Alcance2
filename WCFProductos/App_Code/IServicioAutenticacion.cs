using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ServiceModel;
using System.Runtime.Serialization;

[ServiceContract]
public interface IServicioAutenticacion
{
    [OperationContract]
    ResultadoAutenticacion ValidarLogin(Credenciales credenciales);

    [OperationContract]
    ResultadoRegistro RegistrarUsuario(UsuarioRegistro usuario);
}

[DataContract]
public class Credenciales
{
    [DataMember]
    public string UsuarioEncriptado { get; set; }

    [DataMember]
    public string ContrasenaEncriptada { get; set; }
}

[DataContract]
public class ResultadoAutenticacion
{
    [DataMember]
    public bool Resultado { get; set; }

    [DataMember]
    public string Mensaje { get; set; }

    [DataMember]
    public int TipoUsuario { get; set; }
}

[DataContract]
public class UsuarioRegistro
{
    [DataMember]
    public string Identificacion { get; set; }

    [DataMember]
    public string Nombre { get; set; }

    [DataMember]
    public string PrimerApellido { get; set; }

    [DataMember]
    public string SegundoApellido { get; set; }

    [DataMember]
    public string Email { get; set; }

    [DataMember]
    public string Usuario { get; set; }

    [DataMember]
    public string Contrasena { get; set; }

    [DataMember]
    public int Tipo { get; set; }
}

[DataContract]
public class ResultadoRegistro
{
    [DataMember]
    public bool Exitoso { get; set; }

    [DataMember]
    public string Mensaje { get; set; }
}