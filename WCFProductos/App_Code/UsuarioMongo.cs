using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

/// <summary>
/// Clase para mapear los usuarios en MongoDB
/// </summary>
public class UsuarioMongo
{
    [BsonId]
    public ObjectId Id { get; set; }

    [BsonElement("identificacion")]
    public string Identificacion { get; set; }

    [BsonElement("nombre")]
    public string Nombre { get; set; }

    [BsonElement("primerApellido")]
    public string PrimerApellido { get; set; }

    [BsonElement("segundoApellido")]
    public string SegundoApellido { get; set; }

    [BsonElement("correo")]
    public string Email { get; set; }

    [BsonElement("usuario")]
    public string Usuario { get; set; }

    [BsonElement("contrasena")]
    public string Contrasena { get; set; } // Almacenada ENCRIPTADA

    [BsonElement("estado")]
    public string Estado { get; set; } // "activo" o "inactivo"

    [BsonElement("tipo")]
    public int Tipo { get; set; } // 1=admin, 2=cliente
}