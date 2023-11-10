<?php

namespace AdityaDarma\LaravelJwtSso;

use AdityaDarma\LaravelJwt\Facades\JwtSso;
use Illuminate\Support\ServiceProvider;

class LaravelJwtSsoServiceProvider extends ServiceProvider
{
    /**
     * Publish data.
     *
     * @return void
     */
    private function publish(): void
    {

    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot(): void
    {

    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->app->bind('JwtSso', function(){
            return new Jwt();
        });
        $this->app->bind('CryptSso', function(){
            return new Crypt();
        });
    }
}