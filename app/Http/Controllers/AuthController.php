<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Validation\ValidationException; // ✅ correct import
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    
    public function me(Request $request){
        try {
            $user = $request->user();

            if(!$user){
                return response()->json([
                    'error' => 'Invalid or Expired token'
                ],401);
            }
             return response()->json([
                'status' => 'success',
                'data' => ['user' => $request->user()],
             ]);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Unauthorized.'
            ],401);
        }      
    }

    public function register(Request $request){
  
        $validated  = $request->validate([
            'name'=>'required|string|max:255',
            'email'=>'required|string|email|unique:users,email',
            'password' => 'required|string|min:6',
        ]);

        try {
            $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => $validated['password']
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
             'status' => 'success',
            'user' => $user,
            'token' =>$token
        ]);
        }catch (\Exception $e) {
             return response()->json([
                'status' => 'error',
                'message' => 'Registration failed.',
                'error' => $e->getMessage(),
             ]);
        }
    }

    public function login(Request $request){
        $validated = $request->validate([
            'email'=> 'required|string|email',
            'password'=> 'required|string',
        ]);


        $user = User::where('email',$validated['email'])->first();

        if(!$user || !Hash::check($validated['password'], $user->password)){
            throw ValidationException::withMessages([
                'email' => ['Invalid Credentials'],
            ]);
        }

        $user->tokens()->delete();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'user' => $user,
            'token' => $token
        ]);
    }

    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();
        
        return response()->json([
            'status' => 'success',
            'message' => 'Logged out succesfully'
        ]);
    }

}
