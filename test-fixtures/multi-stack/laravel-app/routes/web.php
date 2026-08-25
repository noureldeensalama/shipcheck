<?php
// Fixture: Laravel routes. The unguarded account route MUST fire; the
// middleware('auth') one MUST NOT. Filler routes keep the pair further apart
// than the ~400-char guard-search window.
use Illuminate\Support\Facades\Route;

Route::get('/health', fn () => response()->json(['ok' => true]));

Route::get('/catalog', [CatalogController::class, 'index']);

Route::post('/newsletter/subscribe', [NewsletterController::class, 'subscribe']);

Route::prefix('public')->group(function () {
    Route::get('/pricing', [PricingController::class, 'index']);
    Route::get('/faq', [FaqController::class, 'index']);
});

Route::get('/account/settings', [AccountController::class, 'edit']);

Route::get('/billing/invoices', [BillingController::class, 'index'])->middleware('auth');
