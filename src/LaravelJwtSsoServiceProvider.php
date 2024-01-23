<?php

namespace AdityaDarma\LaravelJwtSso;

use AdityaDarma\LaravelJwtSso\Facades\SsoJwt;
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
        $this->app->bind('sso-jwt', function(){
            return new Jwt();
        });

        $this->app->bind('sso-crypt', function(){
            return new Crypt();
        });

        $this->app->singleton(SsoJwt::class, function() {
            return new SsoJwt();
        });
    }
}
