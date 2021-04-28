<?php

namespace App\Http\Controllers\auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;

use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request){
        try{
            
            $userExist = User::where([
                'email' => $request->email,
               
            ])->exists();
            if($userExist){
                return response([
                    'message' => 'User exists already'
                ], Response::HTTP_NOT_ACCEPTABLE);
            }
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);
    
            return response([ 'user'=> $user, 'message' => 'Registration successful'], Response::HTTP_CREATED);

        }
        catch(Exception $e){
            return response(['message' => $e->getMessage()],Response::HTTP_INTERNAL_SERVER_ERROR);
        }
        

    }

    public function login(Request $request){
        try{
        $isCorrect = Auth::attempt([
            'email' => $request->email,
            'password' => $request->password
        ]);
        if(!$isCorrect){
            return response(['error' =>
            'Invalid credentials'
            
            ], Response::HTTP_UNAUTHORIZED);
        }
        $user = Auth::user();
        $token = $user->createToken('token')->plainTextToken;
        $jwtCookie = cookie('jwt', $token,60*24);

        return response([
            'user' => $user,
            'token' => $token
        ], Response::HTTP_OK)->withCookie($jwtCookie);
    }
    catch(Exception $e){
        return response(['error' => "Unable to Login to our server"], Response::HTTP_INTERNAL_SERVER_ERROR);
    }


    }

    public function logout(){
        $cookie = Cookie::forget('jwt');

        return response([
        'message' => 'logout successfull'
        ], Response::HTTP_OK)->withCookie($cookie);

    }

    public function checkAuthStatus(){
        
        return response(['message' => 'logged in'], Response::HTTP_OK);
              
    }
}
