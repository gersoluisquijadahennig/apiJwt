<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

    
// Ruta de registro sin middleware de autenticación
Route::post('/register', [AuthController::class, 'register'])->middleware(['EncryptCookies']);

// Ruta de inicio de sesión
Route::post('/login', [AuthController::class, 'login'])->middleware(['EncryptCookies']);
Route::get('/me', [AuthController::class, 'me'])->middleware(['EncryptCookies', 'JwtCookie' ]);
Route::get('/verify', [AuthController::class, 'verify'])->middleware(['EncryptCookies','JwtCookie' ]);
Route::post('/logout', [AuthController::class, 'logout'])->middleware(['EncryptCookies','JwtCookie' ]);
Route::post('/logout-refresh', [AuthController::class, 'logoutRefresh'])->middleware('auth:api');


Route::post('/refresh', [AuthController::class, 'refresh']);
Route::get('/me-token', [AuthController::class, 'me'])->middleware('auth');


