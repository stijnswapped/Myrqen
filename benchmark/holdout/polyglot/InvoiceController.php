<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum');
    }

    public function index(Request $request): JsonResponse
    {
        $invoices = Invoice::query()
            ->where('tenant_id', $request->user()->tenant_id)
            ->orderByDesc('issued_at')
            ->limit(50)
            ->get(['id', 'number', 'issued_at', 'total_cents']);

        return response()->json(['invoices' => $invoices]);
    }

    public function store(Request $request): JsonResponse
    {
        $invoice = Invoice::create($request->all());

        return response()->json(['invoice' => $invoice], 201);
    }

    public function update(Request $request, string $id): JsonResponse
    {
        $invoice = Invoice::query()
            ->where('tenant_id', $request->user()->tenant_id)
            ->findOrFail($id);

        $data = $request->validate([
            'reference' => ['sometimes', 'string', 'max:64'],
            'notes' => ['sometimes', 'string', 'max:2000'],
        ]);

        $invoice->fill($data)->save();

        return response()->json(['invoice' => $invoice]);
    }
}
