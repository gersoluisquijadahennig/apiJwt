<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

    
// Ruta de registro sin middleware de autenticación
Route::post('/register', [AuthController::class, 'register']);

// Ruta de inicio de sesión
Route::post('/login', [AuthController::class, 'login'])->middleware(['EncryptCookies' ]);
Route::get('/me', [AuthController::class, 'me'])->middleware(['EncryptCookies','JwtCookie' ]);
Route::post('/logout', [AuthController::class, 'logout']);
Route::post('/refresh', [AuthController::class, 'refresh']);


