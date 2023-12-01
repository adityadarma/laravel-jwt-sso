<?php

namespace AdityaDarma\LaravelJwtSso;

use Illuminate\Support\ServiceProvider;

class LaravelJwtSsoServiceProvider extends ServiceProvider
{
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
        $this->app->bind('jwt-sso', function(){
            return new Jwt();
        });

        $this->app->bind('crypt-sso', function(){
            return new Crypt();
        });
    }
}
