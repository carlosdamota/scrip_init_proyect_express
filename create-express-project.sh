#!/bin/bash

# Proyecto Node.js + Express con estructura básica y selección de dependencias
# Este script crea un proyecto Node.js con Express, configurado con estructura de carpetas
# y permite seleccionar las dependencias que deseas instalar

echo "=== Creador de Proyectos Node.js + Express ==="
echo ""

# Solicitar nombre del proyecto
read -p "Nombre del proyecto: " PROJECT_NAME

# Verificar si el nombre del proyecto está vacío
if [ -z "$PROJECT_NAME" ]; then
  echo "Error: Debe proporcionar un nombre para el proyecto."
  exit 1
fi

# Crear directorio del proyecto
mkdir "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Inicializar Git
git init

# Inicializar proyecto Node.js
echo "Inicializando proyecto Node.js..."
npm init -y

# Dependencias básicas (siempre se instalan)
BASIC_DEPS="express cors dotenv"

# Función para preguntar sí/no
ask_yes_no() {
  while true; do
    read -p "$1 (s/n): " yn
    case $yn in
      [Ss]* ) return 0;;
      [Nn]* ) return 1;;
      * ) echo "Por favor, responde s (sí) o n (no).";;
    esac
  done
}

# Seleccionar dependencias opcionales
OPTIONAL_DEPS=""

# Mongoose (MongoDB)
if ask_yes_no "¿Deseas instalar Mongoose para MongoDB?"; then
  OPTIONAL_DEPS="$OPTIONAL_DEPS mongoose"
fi

# Logging
if ask_yes_no "¿Deseas instalar Morgan para logging?"; then
  OPTIONAL_DEPS="$OPTIONAL_DEPS morgan"
fi

# Seguridad
if ask_yes_no "¿Deseas instalar paquetes de seguridad (helmet, express-rate-limit)?"; then
  OPTIONAL_DEPS="$OPTIONAL_DEPS helmet express-rate-limit"
fi

# Autenticación
if ask_yes_no "¿Deseas instalar paquetes para autenticación (jsonwebtoken, bcryptjs)?"; then
  OPTIONAL_DEPS="$OPTIONAL_DEPS jsonwebtoken bcryptjs"
fi

# Validación
if ask_yes_no "¿Deseas instalar paquetes para validación (express-validator, joi)?"; then
  OPTIONAL_DEPS="$OPTIONAL_DEPS express-validator joi"
fi

# Utilidades
if ask_yes_no "¿Deseas instalar utilidades adicionales (cookie-parser)?"; then
  OPTIONAL_DEPS="$OPTIONAL_DEPS cookie-parser"
fi

# Herramientas de desarrollo
DEV_DEPS="nodemon"
if ask_yes_no "¿Deseas instalar herramientas de testing y linting (jest, supertest, eslint)?"; then
  DEV_DEPS="$DEV_DEPS jest supertest eslint"
fi

# Instalar dependencias básicas y opcionales
echo "Instalando dependencias básicas y opcionales seleccionadas..."
npm install $BASIC_DEPS $OPTIONAL_DEPS

# Instalar dependencias de desarrollo
echo "Instalando dependencias de desarrollo..."
npm install --save-dev $DEV_DEPS

# Crear estructura de carpetas
echo "Creando estructura de carpetas..."
mkdir controllers models routes config middleware public utils
if [[ $DEV_DEPS == *"jest"* ]]; then
  mkdir tests
fi

# Variables para usar en la generación de archivos
HAS_MONGOOSE=$(echo $OPTIONAL_DEPS | grep -q "mongoose" && echo "true" || echo "false")
HAS_MORGAN=$(echo $OPTIONAL_DEPS | grep -q "morgan" && echo "true" || echo "false")
HAS_HELMET=$(echo $OPTIONAL_DEPS | grep -q "helmet" && echo "true" || echo "false")
HAS_RATE_LIMIT=$(echo $OPTIONAL_DEPS | grep -q "express-rate-limit" && echo "true" || echo "false")
HAS_JWT=$(echo $OPTIONAL_DEPS | grep -q "jsonwebtoken" && echo "true" || echo "false")
HAS_COOKIE_PARSER=$(echo $OPTIONAL_DEPS | grep -q "cookie-parser" && echo "true" || echo "false")
HAS_EXPRESS_VALIDATOR=$(echo $OPTIONAL_DEPS | grep -q "express-validator" && echo "true" || echo "false")

# Crear archivo principal
echo "Creando archivo principal (app.js)..."
cat > app.js << EOL
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
EOL

# Agregar imports según dependencias seleccionadas
if [ "$HAS_MORGAN" = "true" ]; then
  echo "const morgan = require('morgan');" >> app.js
fi

if [ "$HAS_HELMET" = "true" ]; then
  echo "const helmet = require('helmet');" >> app.js
fi

if [ "$HAS_RATE_LIMIT" = "true" ]; then
  echo "const rateLimit = require('express-rate-limit');" >> app.js
fi

if [ "$HAS_COOKIE_PARSER" = "true" ]; then
  echo "const cookieParser = require('cookie-parser');" >> app.js
fi

# Continuar con el contenido del archivo app.js
cat >> app.js << EOL

// Cargar variables de entorno
dotenv.config();

// Inicializar Express
const app = express();
const PORT = process.env.PORT || 3000;
EOL

# Agregar rate limiting si está seleccionado
if [ "$HAS_RATE_LIMIT" = "true" ]; then
  cat >> app.js << EOL

// Configuración de rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // límite de 100 solicitudes por ventana
  standardHeaders: true,
  legacyHeaders: false,
});
EOL
fi

# Agregar middlewares
cat >> app.js << EOL

// Middlewares
EOL

if [ "$HAS_HELMET" = "true" ]; then
  echo "app.use(helmet()); // Seguridad HTTP" >> app.js
fi

cat >> app.js << EOL
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
EOL

if [ "$HAS_COOKIE_PARSER" = "true" ]; then
  echo "app.use(cookieParser());" >> app.js
fi

if [ "$HAS_MORGAN" = "true" ]; then
  echo "app.use(morgan('dev'));" >> app.js
fi

if [ "$HAS_RATE_LIMIT" = "true" ]; then
  echo "app.use(limiter); // Aplicar rate limiting a todas las solicitudes" >> app.js
fi

# Agregar conexión a MongoDB si Mongoose está seleccionado
if [ "$HAS_MONGOOSE" = "true" ]; then
  cat >> app.js << EOL

// Conectar a MongoDB
const connectDB = require('./config/db');
connectDB();
EOL
fi

# Continuar con rutas y manejo de errores
cat >> app.js << EOL

// Rutas
const indexRouter = require('./routes/index');
app.use('/', indexRouter);
EOL

if [ "$HAS_EXPRESS_VALIDATOR" = "true" ]; then
  echo "const apiRouter = require('./routes/api');" >> app.js
  echo "app.use('/api', apiRouter);" >> app.js
fi

cat >> app.js << EOL

// Manejo de errores 404
app.use((req, res) => {
  res.status(404).json({ message: 'Ruta no encontrada' });
});

// Middleware de manejo de errores global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.statusCode || 500).json({
    message: err.message || 'Error interno del servidor',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(\`Servidor corriendo en http://localhost:\${PORT}\`);
});

module.exports = app;
EOL

# Crear archivo de configuración de DB si Mongoose está seleccionado
if [ "$HAS_MONGOOSE" = "true" ]; then
  echo "Creando configuración de base de datos..."
  mkdir -p config
  cat > config/db.js << EOL
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    console.log(\`MongoDB conectado: \${conn.connection.host}\`);
  } catch (error) {
    console.error(\`Error de conexión a MongoDB: \${error.message}\`);
    process.exit(1);
  }
};

module.exports = connectDB;
EOL
fi

# Crear archivo de rutas index
echo "Creando rutas básicas..."
mkdir -p routes
cat > routes/index.js << EOL
const express = require('express');
const router = express.Router();

// Ruta de bienvenida
router.get('/', (req, res) => {
  res.json({ message: 'Bienvenido a la API' });
});

module.exports = router;
EOL

# Crear archivo de rutas API si express-validator está seleccionado
if [ "$HAS_EXPRESS_VALIDATOR" = "true" ]; then
  cat > routes/api.js << EOL
const express = require('express');
const router = express.Router();
const { check } = require('express-validator');
const exampleController = require('../controllers/exampleController');

// Ruta GET de ejemplo
router.get('/examples', exampleController.getExamples);

// Ruta POST de ejemplo con validación
router.post(
  '/examples',
  [
    check('name', 'El nombre es obligatorio').not().isEmpty(),
    check('description', 'La descripción debe tener al menos 10 caracteres').isLength({ min: 10 })
  ],
  exampleController.createExample
);

// Ruta GET para un elemento específico
router.get('/examples/:id', exampleController.getExampleById);

module.exports = router;
EOL

  # Crear un ejemplo de controlador con express-validator
  echo "Creando controlador de ejemplo..."
  mkdir -p controllers
  cat > controllers/exampleController.js << EOL
const { validationResult } = require('express-validator');
EOL

  if [ "$HAS_MONGOOSE" = "true" ]; then
    echo "const Example = require('../models/exampleModel');" >> controllers/exampleController.js
  fi

  cat >> controllers/exampleController.js << EOL

// Obtener todos los ejemplos
exports.getExamples = async (req, res) => {
  try {
EOL

  if [ "$HAS_MONGOOSE" = "true" ]; then
    echo "    const examples = await Example.find();" >> controllers/exampleController.js
    echo "    res.json(examples);" >> controllers/exampleController.js
  else
    echo "    // Ejemplo sin base de datos - simulación" >> controllers/exampleController.js
    echo "    const examples = [{id: 1, name: 'Ejemplo 1', description: 'Descripción del ejemplo 1'}];" >> controllers/exampleController.js
    echo "    res.json(examples);" >> controllers/exampleController.js
  fi

  cat >> controllers/exampleController.js << EOL
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: 'Error del servidor' });
  }
};

// Crear un nuevo ejemplo
exports.createExample = async (req, res) => {
  // Verificar errores de validación
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { name, description } = req.body;
    
EOL

  if [ "$HAS_MONGOOSE" = "true" ]; then
    cat >> controllers/exampleController.js << EOL
    // Crear nuevo ejemplo
    const example = new Example({
      name,
      description
    });
    
    // Guardar en la base de datos
    await example.save();
EOL
  else
    cat >> controllers/exampleController.js << EOL
    // Ejemplo sin base de datos - simulación
    const example = {
      id: Math.floor(Math.random() * 1000),
      name,
      description,
      createdAt: new Date()
    };
EOL
  fi

  cat >> controllers/exampleController.js << EOL
    
    res.status(201).json({ message: 'Recurso creado exitosamente', data: example });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: 'Error del servidor' });
  }
};

// Obtener un ejemplo por ID
exports.getExampleById = async (req, res) => {
  try {
EOL

  if [ "$HAS_MONGOOSE" = "true" ]; then
    cat >> controllers/exampleController.js << EOL
    const example = await Example.findById(req.params.id);
    
    if (!example) {
      return res.status(404).json({ message: 'Recurso no encontrado' });
    }
EOL
  else
    cat >> controllers/exampleController.js << EOL
    // Ejemplo sin base de datos - simulación
    const example = {id: req.params.id, name: 'Ejemplo', description: 'Descripción del ejemplo'};
    
    // Simular búsqueda
    if (req.params.id === '999') {
      return res.status(404).json({ message: 'Recurso no encontrado' });
    }
EOL
  fi

  cat >> controllers/exampleController.js << EOL
    
    res.json(example);
  } catch (err) {
    console.error(err.message);
EOL

  if [ "$HAS_MONGOOSE" = "true" ]; then
    echo "    if (err.kind === 'ObjectId') {" >> controllers/exampleController.js
    echo "      return res.status(404).json({ message: 'Recurso no encontrado' });" >> controllers/exampleController.js
    echo "    }" >> controllers/exampleController.js
  fi

  cat >> controllers/exampleController.js << EOL
    res.status(500).json({ message: 'Error del servidor' });
  }
};
EOL
else
  # Crear un controlador simple sin express-validator
  echo "Creando controlador de ejemplo..."
  mkdir -p controllers
  cat > controllers/exampleController.js << EOL
// Ejemplo de un controlador

exports.getExample = (req, res) => {
  res.json({ message: 'Ejemplo de respuesta desde el controlador' });
};

exports.createExample = (req, res) => {
  const data = req.body;
  // Lógica para crear un recurso
  res.status(201).json({ message: 'Recurso creado', data });
};
EOL
fi

# Crear modelo si Mongoose está seleccionado
if [ "$HAS_MONGOOSE" = "true" ]; then
  echo "Creando modelo de ejemplo..."
  mkdir -p models
  cat > models/exampleModel.js << EOL
const mongoose = require('mongoose');

const exampleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    minlength: 10
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'pending'],
    default: 'active'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Example', exampleSchema);
EOL
fi

# Crear middleware de autenticación si JWT está seleccionado
if [ "$HAS_JWT" = "true" ]; then
  echo "Creando middleware de autenticación..."
  mkdir -p middleware
  cat > middleware/auth.js << EOL
const jwt = require('jsonwebtoken');

module.exports = function(req, res, next) {
  // Obtener el token del header
  const token = req.header('x-auth-token');

  // Verificar si no hay token
  if (!token) {
    return res.status(401).json({ message: 'No hay token, autorización denegada' });
  }

  try {
    // Verificar el token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Agregar el usuario desde el payload
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token no válido' });
  }
};
EOL
fi

# Crear utilidades comunes
echo "Creando utilidades comunes..."
mkdir -p utils
cat > utils/errorHandler.js << EOL
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
EOL

# Crear test unitario si Jest está seleccionado
if [[ $DEV_DEPS == *"jest"* ]]; then
  echo "Creando test unitario básico..."
  mkdir -p tests
  cat > tests/example.test.js << EOL
EOL

  if [ "$HAS_MONGOOSE" = "true" ]; then
    cat >> tests/example.test.js << EOL
const mongoose = require('mongoose');
const Example = require('../models/exampleModel');

// Mock de datos
const exampleData = {
  name: 'Test Example',
  description: 'This is a test description for our model'
};

// Antes de todos los tests
beforeAll(async () => {
  // Conexión a la base de datos de prueba
  const url = process.env.MONGO_URI || 'mongodb://localhost:27017/test_db';
  await mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });
});

// Después de todos los tests
afterAll(async () => {
  await mongoose.connection.close();
});

// Limpiar la colección después de cada test
afterEach(async () => {
  await Example.deleteMany();
});

describe('Example Model Test', () => {
  it('should create & save an example successfully', async () => {
    const validExample = new Example(exampleData);
    const savedExample = await validExample.save();
    
    // Verificar el id del objeto guardado
    expect(savedExample._id).toBeDefined();
    expect(savedExample.name).toBe(exampleData.name);
    expect(savedExample.description).toBe(exampleData.description);
    expect(savedExample.status).toBe('active'); // valor por defecto
  });
  
  it('should fail when required fields are missing', async () => {
    const exampleWithoutName = new Example({ description: 'Test description' });
    let err;
    
    try {
      await exampleWithoutName.save();
    } catch (error) {
      err = error;
    }
    
    expect(err).toBeInstanceOf(mongoose.Error.ValidationError);
  });
});
EOL
  else
    cat >> tests/example.test.js << EOL
// Test básico sin base de datos
const exampleController = require('../controllers/exampleController');

// Mock para req y res
const mockRequest = () => {
  return {
    body: {},
    params: {}
  };
};

const mockResponse = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('Example Controller Test', () => {
  it('should return a message for getExample', () => {
    const req = mockRequest();
    const res = mockResponse();
    
    exampleController.getExample(req, res);
    
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.any(String)
      })
    );
  });
  
  it('should create an example and return status 201', () => {
    const req = mockRequest();
    req.body = { name: 'Test' };
    const res = mockResponse();
    
    exampleController.createExample(req, res);
    
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.any(String),
        data: expect.any(Object)
      })
    );
  });
});
EOL
  fi
fi

# Crear archivos de configuración
echo "Creando archivos de configuración..."

# .env
cat > .env << EOL
PORT=3000
EOL

if [ "$HAS_MONGOOSE" = "true" ]; then
  echo "MONGO_URI=mongodb://localhost:27017/${PROJECT_NAME}" >> .env
fi

echo "NODE_ENV=development" >> .env

if [ "$HAS_JWT" = "true" ]; then
  echo "JWT_SECRET=my_ultra_secure_secret_key_change_in_production" >> .env
  echo "JWT_EXPIRES_IN=1d" >> .env
fi

# .gitignore
cat > .gitignore << EOL
# Dependencias
node_modules/
npm-debug.log
yarn-error.log

# Entorno
.env
.env.local
.env.*.local

# Logs
logs
*.log

# Directorios de sistema
.DS_Store
Thumbs.db
EOL

if [[ $DEV_DEPS == *"jest"* ]]; then
  echo "# Cobertura de tests" >> .gitignore
  echo "coverage/" >> .gitignore
fi

echo "# Directorio de construcción" >> .gitignore
echo "dist/" >> .gitignore
echo "build/" >> .gitignore

# Configuración básica de ESLint si está seleccionado
if [[ $DEV_DEPS == *"eslint"* ]]; then
  cat > .eslintrc.json << EOL
{
  "env": {
    "node": true,
    "commonjs": true,
    "es2021": true
EOL

  if [[ $DEV_DEPS == *"jest"* ]]; then
    echo '    ,"jest": true' >> .eslintrc.json
  fi

  cat >> .eslintrc.json << EOL
  },
  "extends": "eslint:recommended",
  "parserOptions": {
    "ecmaVersion": 12
  },
  "rules": {
    "no-console": "warn",
    "no-unused-vars": ["error", { "argsIgnorePattern": "next" }]
  }
}
EOL
fi

# Actualizar package.json para agregar scripts
echo "Configurando scripts en package.json..."
node -e "
const fs = require('fs');
const packageJson = JSON.parse(fs.readFileSync('./package.json'));
packageJson.scripts = {
  ...packageJson.scripts,
  'start': 'node app.js',
  'dev': 'nodemon app.js'
};
" + "
if ('$DEV_DEPS'.includes('jest')) {
  packageJson.scripts = {
    ...packageJson.scripts,
    'test': 'jest',
    'test:watch': 'jest --watch'
  };
}
if ('$DEV_DEPS'.includes('eslint')) {
  packageJson.scripts = {
    ...packageJson.scripts,
    'lint': 'eslint .'
  };
}
packageJson.main = 'app.js';
fs.writeFileSync('./package.json', JSON.stringify(packageJson, null, 2));
"

# Crear README.md básico
echo "Creando README.md..."
cat > README.md << EOL
# ${PROJECT_NAME}

Proyecto de API con Node.js y Express

## Instalación

\`\`\`
npm install
\`\`\`

## Configuración

Crea un archivo \`.env\` en la raíz del proyecto con las siguientes variables:

\`\`\`
PORT=3000
EOL

if [ "$HAS_MONGOOSE" = "true" ]; then
  echo "MONGO_URI=mongodb://localhost:27017/${PROJECT_NAME}" >> README.md
fi

echo "NODE_ENV=development" >> README.md

if [ "$HAS_JWT" = "true" ]; then
  echo "JWT_SECRET=your_secret_key" >> README.md
  echo "JWT_EXPIRES_IN=1d" >> README.md
fi

cat >> README.md << EOL
\`\`\`

## Ejecución en desarrollo

\`\`\`
npm run dev
\`\`\`

## Ejecución en producción

\`\`\`
npm start
\`\`\`
EOL

if [[ $DEV_DEPS == *"jest"* ]]; then
  echo "" >> README.md
  echo "## Tests" >> README.md
  echo "" >> README.md
  echo "\`\`\`" >> README.md
  echo "npm test" >> README.md
  echo "\`\`\`" >> README.md
fi

cat >> README.md << EOL

## Estructura de carpetas

- \`controllers/\`: Lógica de negocio
- \`models/\`: Modelos de datos
- \`routes/\`: Rutas de la API
- \`middleware/\`: Middlewares personalizados
- \`config/\`: Archivos de configuración
- \`utils/\`: Utilidades y helpers
EOL

if [[ $DEV_DEPS == *"jest"* ]]; then
  echo "- \`tests/\`: Tests unitarios e integración" >> README.md
fi

echo "- \`public/\`: Archivos estáticos" >> README.md

cat >> README.md << EOL

## Dependencias instaladas

- Express: Framework web
- CORS: Middleware para habilitar CORS
- Dotenv: Para variables de entorno
EOL

if [ "$HAS_MONGOOSE" = "true" ]; then
  echo "- Mongoose: ODM para MongoDB" >> README.md
fi

if [ "$HAS_MORGAN" = "true" ]; then
  echo "- Morgan: Logging HTTP" >> README.md
fi

if [ "$HAS_HELMET" = "true" ]; then
  echo "- Helmet: Seguridad HTTP" >> README.md
fi

if [ "$HAS_RATE_LIMIT" = "true" ]; then
  echo "- Express Rate Limit: Protección contra ataques de fuerza bruta" >> README.md
fi

if [ "$HAS_JWT" = "true" ]; then
  echo "- JSON Web Token: Autenticación basada en tokens" >> README.md
  echo "- Bcryptjs: Cifrado de contraseñas" >> README.md
fi

if [ "$HAS_EXPRESS_VALIDATOR" = "true" ]; then
  echo "- Express Validator: Validación de datos" >> README.md
fi

if [[ $OPTIONAL_DEPS == *"joi"* ]]; then
  echo "- Joi: Validación de esquemas" >> README.md
fi

if [ "$HAS_COOKIE_PARSER" = "true" ]; then
  echo "- Cookie Parser: Manejo de cookies" >> README.md
fi

echo "" >> README.md
echo "### Dependencias de desarrollo" >> README.md
echo "" >> README.md
echo "- Nodemon: Reinicio automático del servidor" >> README.md

if [[ $DEV_DEPS == *"jest"* ]]; then
  echo "- Jest: Framework de testing" >> README.md
fi

if [[ $DEV_DEPS == *"supertest"* ]]; then
  echo "- Supertest: Testing de API" >> README.md
fi

if [[ $DEV_DEPS == *"eslint"* ]]; then
  echo "- ESLint: Linting de código" >> README.md
fi

echo ""
echo "✅ Proyecto '${PROJECT_NAME}' creado exitosamente!"
echo ""
echo "Resumen de dependencias instaladas:"
echo "- Básicas: $BASIC_DEPS"
echo "- Opcionales: $OPTIONAL_DEPS"
echo "- Desarrollo: $DEV_DEPS"
echo ""
echo "Para ejecutar tu proyecto:"
echo "  cd ${PROJECT_NAME}"
echo "  npm run dev"
echo ""
echo "¡Feliz desarrollo! 🚀"