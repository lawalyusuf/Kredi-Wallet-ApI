<?php

namespace App\Http\Controllers\v1;
use Carbon\Carbon;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use App\Models\Transaction;
use App\Http\Requests\BankChargeRequest;
use App\Notifications\RegisterNotification;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    
    public function register(Request $request)
    {
        $messages = [
            'name.required' => 'Fullname is required',
            'name.string' => 'Fullname must be a string',
            'email.required' => 'Email is required',
            'email.email' => 'Email must be a vaild email address',
            'password.required' => 'Password is required',
        ];

        $rules = [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string',
        ];

        $validator = Validator::make($request->all(), $rules, $messages);

        if($validator->fails()){
            return response()->json([
                'message' => 'validation fails',
                'errors' => $validator->errors()
            ],404);
        }

        $user = new User();

        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
    
        $user->save();
        return $this->login($request);


    }


    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized, Email and Password not valiid'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function user()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }


    public function forgot(Request $request)
    {
        $messages = [
            'email.required' => 'Email is required',
            'email.email' => 'Email must be a vaild email address',
        ];

        $rules = [
            'email' => 'required|email',
        ];

        $validator = Validator::make($request->all(), $rules, $messages);

        if($validator->fails()){
            return response()->json([
                'message' => 'validation fails',
                'errors' => $validator->errors()
            ],404);
        }

        $user = User::where('email', $request->email)->first(['email', 'name']);

        if(!$user){
            return response()->json([
                'error' => 'user not found',
            ],404);
        }else{
            $code = rand(10000, 99999);
            //delete the old password
            $codes = DB::table('password_resets')->where('email', $user->email)->delete();
            //set new password
            $data = ['email' => $user->email, 'token' => $code, 'created_at' => Carbon::now(), 'expired_at' => Carbon::now()->addMinutes(15)];
            $insert = DB::table('password_resets')->insert($data);

            $expire = Carbon::now()->addMinutes(15)->format('d M Y H:i:A');

            try {
                $sendMail = \Mail::send('emails.otp',['user' => $user, 'code' => $code, 'expire' => $expire],function ($message) use($user){
                    $subject = "Your One Time Password";
                    $message->to($user->email, $user->name);
                    // $message->to('bwitlawalyusuf@gmail.com', 'Lawal Yusuf');
                    $message->subject($subject);
                    $message->from('no-reply@naturesfx.com', 'Kredi Money');
                });

            } catch (\Throwable $th) {
                return $th;
            }

            return response()->json([
                'message' => 'ok',
                'user' => $user
            ],200);
        }
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request)
    {
        $user = auth('api')->user();
        $user->update($request->all());
        return response()->json([
            'status' => 'success',
        ],200);
    }


    public function deposit(BankChargeRequest $request){
        $response = Http::withToken($this->paystack_secret)->post($this->bank_charge,[
            "email" => auth('api')->user()->email,
            "amount" => $request->amount,
            "bank" => [
                "code" =>  $request->bank_code,
                "account_number" => $request->account_number,
            ],
        ]);
        return $response->json();
    }
}
