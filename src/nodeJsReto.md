
Vulnerabilidad 1:

Broken Authentication en la siguiente línea:

 `res.status(401).json({ message: 'Invalid Authentication Credentials' });`

 Aunque la línea simplemente informa que las credenciales no son válidas, proporcionar detalles específicos como "credenciales inválidas" puede ser útil para atacantes que buscan confirmar que:

- La cabecera de autenticación fue procesada correctamente.
- El formato de las credenciales es correcto (pero no válido). Esto puede dar pistas sobre la estructura o configuración del sistema, lo que ayuda a refinar ataques posteriores.
- Si no se asegura que se devuelva una respuesta inmediatamente después de la llamada `res.status(401).json(...)`, el `next()` se ejecutará, lo que podría permitir el acceso no autorizado.

Vulnerabilidad 2:

Falta de Rate Limiting

- Si no implementas un sistema de rate limiting, los atacantes pueden realizar ataques de fuerza bruta para probar diferentes combinaciones de credenciales sin restricciones.

Con la siguiente herramienta se puede probar miles de combinaciones en poco tiempo, ya que como menciono arriba no existen restricciones para probar credenciales.  

**Uso de Hydra para explotación del rate limiting**

"hydra -l admin -P rockyou.txt localhost http-get / "

**Codigo corregido.**

import express, { Request, Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";

const app = express();

const limiter = rateLimit({
  windowMs: 15 *60* 1000,
  max: 50,
  message: { message: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

function basicAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return res
      .status(401)
      .setHeader("WWW-Authenticate", "Basic realm=\"Access to API\"")
      .json({ message: "Unauthorized" });
  }

  try {
    const base64Credentials = authHeader.split[" "](1);
    const credentials = Buffer.from(base64Credentials, "base64").toString("utf8");
    const [username, password] = credentials.split(":");

    if (
      username !== process.env.MYUSER ||
      password !== process.env.MYPASSWORD
    ) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    next();
  } catch (err) {
    return res.status(400).json({ message: "Unauthorized" });
  }
}

app.use(basicAuth);

app.get("/", (req: Request, res: Response) => {
  res.json({ message: "Welcome" });
});

export default app;
