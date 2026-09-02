/**
 * ============================================
 * MIDDLEWARE DE ROLES - MarketCOL
 * ============================================
 * Control de acceso según el rol del usuario.
 */

/**
 * Verifica que exista un usuario autenticado.
 *
 * @param {Object} req - Request de Express
 * @param {Object} res - Response de Express
 * @returns {boolean} true si existe usuario, false si no
 */
const verificarUsuarioAutenticado = (req, res) => {
  if (!req.usuario) {
    res.status(401).json({
      success: false,
      message: 'No autorizado. Debes iniciar sesión primero'
    });

    return false;
  }

  return true;
};

/**
 * Genera una respuesta cuando el usuario no tiene los permisos necesarios.
 *
 * @param {Object} res - Response de Express
 * @param {string} message - Mensaje de error
 * @returns {Object} Response de Express
 */
const accesoDenegado = (res, message) => {
  return res.status(403).json({
    success: false,
    message
  });
};

/**
 * Maneja errores internos de los middlewares.
 *
 * @param {Object} res - Response de Express
 * @param {Error} error - Error generado
 * @param {string} middleware - Nombre del middleware
 * @returns {Object} Response de Express
 */
const errorInterno = (res, error, middleware) => {
  console.error(`Error en middleware ${middleware}:`, error);

  return res.status(500).json({
    success: false,
    message: 'Error al verificar permisos',
    error: error.message
  });
};

/**
 * ============================================
 * esAdministrador
 * ============================================
 * Solo permite acceso a usuarios con rol
 * 'administrador'.
 */
const esAdministrador = (req, res, next) => {
  try {
    if (!verificarUsuarioAutenticado(req, res)) {
      return;
    }

    if (req.usuario.rol !== 'administrador') {
      return accesoDenegado(
        res,
        'Acceso denegado. Se requieren permisos de administrador'
      );
    }

    next();

  } catch (error) {
    return errorInterno(res, error, 'esAdministrador');
  }
};

/**
 * ============================================
 * esCliente
 * ============================================
 * Solo permite acceso a usuarios con rol
 * 'cliente'.
 *
 * Se utiliza en funcionalidades como el
 * carrito de compras.
 */
const esCliente = (req, res, next) => {
  try {
    if (!verificarUsuarioAutenticado(req, res)) {
      return;
    }

    if (req.usuario.rol !== 'cliente') {
      return accesoDenegado(
        res,
        'Acceso denegado. Esta función es solo para clientes'
      );
    }

    next();

  } catch (error) {
    return errorInterno(res, error, 'esCliente');
  }
};

/**
 * ============================================
 * tieneRol
 * ============================================
 * Permite acceso a múltiples roles.
 *
 * Ejemplo:
 * tieneRol(['cliente', 'administrador'])
 */
const tieneRol = (rolesPermitidos) => {

  return (req, res, next) => {
    try {
      if (!verificarUsuarioAutenticado(req, res)) {
        return;
      }

      if (!rolesPermitidos.includes(req.usuario.rol)) {
        return accesoDenegado(
          res,
          `Acceso denegado. Se requiere uno de los siguientes roles: ${rolesPermitidos.join(', ')}`
        );
      }

      next();

    } catch (error) {
      return errorInterno(res, error, 'tieneRol');
    }
  };
};

/**
 * ============================================
 * esPropioUsuarioOAdmin
 * ============================================
 * Permite que un usuario acceda únicamente
 * a sus propios datos.
 *
 * Los administradores pueden acceder a los
 * datos de cualquier usuario.
 */
const esPropioUsuarioOAdmin = (req, res, next) => {
  try {
    if (!verificarUsuarioAutenticado(req, res)) {
      return;
    }

    // Los administradores tienen acceso total.
    if (req.usuario.rol === 'administrador') {
      return next();
    }

    // Puede utilizar :usuarioId o :id según la ruta.
    const usuarioIdParam = req.params.usuarioId || req.params.id;

    const usuarioId = Number.parseInt(usuarioIdParam, 10);

    if (usuarioId !== req.usuario.id) {
      return accesoDenegado(
        res,
        'Acceso denegado. No puedes acceder a datos de otros usuarios'
      );
    }

    next();

  } catch (error) {
    return errorInterno(res, error, 'esPropioUsuarioOAdmin');
  }
};

/**
 * ============================================
 * esAdminOAuxiliar
 * ============================================
 * Permite acceso a administradores y auxiliares.
 */
const esAdminOAuxiliar = (req, res, next) => {
  try {
    if (!verificarUsuarioAutenticado(req, res)) {
      return;
    }

    const rolesPermitidos = ['administrador', 'auxiliar'];

    if (!rolesPermitidos.includes(req.usuario.rol)) {
      return accesoDenegado(
        res,
        'Acceso denegado. Se requieren permisos de administrador o auxiliar'
      );
    }

    next();
  } catch (error) {
    return errorInterno(res, error, 'esAdminOAuxiliar');
  }
};

/**
 * ============================================
 * soloAdministrador
 * ============================================
 * Solo permite acceso a administradores.
 *
 * Se utiliza para operaciones críticas.
 */
const soloAdministrador = (req, res, next) => {
  try {
    if (!verificarUsuarioAutenticado(req, res)) {
      return;
    }

    if (req.usuario.rol !== 'administrador') {
      return accesoDenegado(
        res,
        'Acceso denegado. Solo administradores pueden realizar esta operación'
      );
    }

    next();
  } catch (error) {
    return errorInterno(res, error, 'soloAdministrador');
  }
};

/**
 * ============================================
 * EXPORTACIÓN
 * ============================================
 */
module.exports = {
  esAdministrador,
  esCliente,
  tieneRol,
  esPropioUsuarioOAdmin,
  esAdminOAuxiliar,
  soloAdministrador
};
