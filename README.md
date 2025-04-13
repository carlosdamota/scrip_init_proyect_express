# Node Express Project Creator

Un script interactivo para la consola que automatiza la creación de proyectos Node.js con Express, permitiendo seleccionar dependencias específicas y generando una estructura de directorios organizada lista para comenzar a desarrollar.

## Características

- **Interactivo**: Permite seleccionar exactamente qué dependencias instalar
- **Rápido**: Crea en segundos una estructura de proyecto completa y funcional
- **Personalizable**: Configura tu proyecto con las herramientas que necesitas
- **Bien organizado**: Genera una estructura de carpetas siguiendo buenas prácticas
- **Listo para usar**: Incluye archivos base y ejemplos para comenzar a trabajar inmediatamente

## Dependencias seleccionables

### Básicas (incluidas siempre)
- Express
- CORS
- Dotenv

### Opcionales
- **Base de datos**: Mongoose (MongoDB)
- **Logging**: Morgan
- **Seguridad**: Helmet, Express Rate Limit
- **Autenticación**: JWT, Bcrypt
- **Validación**: Express Validator, Joi
- **Utilidades**: Cookie Parser

### Desarrollo
- **Estándar**: Nodemon
- **Testing y calidad**: Jest, Supertest, ESLint

## Estructura generada

```
proyecto/
├── app.js                 # Punto de entrada principal
├── package.json           # Configuración de dependencias
├── .env                   # Variables de entorno
├── .gitignore             # Archivos a ignorar en Git
├── README.md              # Documentación del proyecto
├── controllers/           # Lógica de negocio
├── models/                # Modelos de datos
├── routes/                # Definición de rutas API
├── middleware/            # Middlewares personalizados
├── config/                # Archivos de configuración
├── utils/                 # Utilidades y helpers
├── public/                # Archivos estáticos
└── tests/                 # Tests unitarios e integración (opcional)
```

## Uso

1. Clone este repositorio o descargue el script
2. Asegúrese que el script tiene permisos de ejecución: `chmod +x create-express-project.sh`
3. Ejecute el script desde Git Bash: `./create-express-project.sh`
4. Siga las instrucciones para configurar su proyecto
5. ¡Empiece a desarrollar!

## Requisitos

- Git Bash o terminal compatible con Bash
- Node.js y npm instalados
- Conexión a internet para descargar paquetes

## Ventajas

- Ahorra tiempo en la configuración inicial
- Mantiene consistencia entre diferentes proyectos
- Implementa mejores prácticas de estructura
- Facilita la adopción de herramientas de calidad como testing y linting
- Incluye configuraciones de seguridad básicas
