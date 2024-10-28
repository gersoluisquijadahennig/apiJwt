<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Http\Request;
use Exception;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Symfony\Component\HttpFoundation\Response;

class JwtCookieMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            // Leer el JWT desde la cookie
            $token = $request->cookie('access_token'); // Asegúrate de que el nombre coincide con tu cookie

            if (!$token) {
                return response()->json(['error' => 'Token not provided., user not authenticate'], Response::HTTP_UNAUTHORIZED);
            }

            // Intentar autenticar usando el token
            $user = JWTAuth::setToken($token)->authenticate();

            if (!$user) {
                return response()->json(['error' => 'User not found.'], Response::HTTP_UNAUTHORIZED);
            }

        } catch (TokenExpiredException $e) {
            // El token ha expirado, intentar refrescar
            try {
                $refreshToken = JWTAuth::refresh($token);

                // Actualizar la cookie con el nuevo token
                $cookie = cookie('access_token', $refreshToken);
                $user = JWTAuth::setToken($refreshToken)->authenticate();
                
                $response = $next($request);

                // Añadir la cookie y la cabecera a la respuesta
                return $response->cookie($cookie);
            } catch (Exception $e) {
                return response()->json(['error' => 'Token refresh failed.'], Response::HTTP_UNAUTHORIZED);
            }
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'Token invalid.'], Response::HTTP_UNAUTHORIZED);
        } catch (Exception $e) {
            return response()->json(['error' => 'Could not authenticate token.'], Response::HTTP_UNAUTHORIZED);
        }

        // Continuar con la solicitud si la autenticación es exitosa
        return $next($request);
    }
}
