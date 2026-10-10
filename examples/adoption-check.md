# jev-sentinel — contrôle d’adoption · adoption check · comprobación de adopción

## Français

Point de départ hors ligne : `npm run demo:key-canary`.

Placez un canari synthétique dans une clé d’objet, pas seulement dans une valeur. Le rapport doit signaler la fuite sans recopier le canari dans l’extrait.

## English

Offline starting point: `npm run demo:key-canary`.

Put a synthetic canary in an object key, not only a value. The report should flag the leak without copying the canary into the excerpt.

## Español

Punto de partida sin conexión: `npm run demo:key-canary`.

Coloque un canario sintético en una clave de objeto, no solo en un valor. El informe debe detectar la fuga sin copiar el canario en el extracto.

## Données fictives · Fictional data · Datos ficticios

```text
object_key="canary_value"; object_value="safe"
```

FR : adaptez une copie de la fixture locale ; ce cas n’est pas une mesure de performance ou de qualité Jev.

EN: adapt a copy of the local fixture; this case is not a Jev performance or quality measurement.

ES: adapte una copia de la fixture local; este caso no mide el rendimiento ni la calidad de Jev.
