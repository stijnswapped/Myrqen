<?php

namespace App\Http\Controllers;

use App\Models\CreditNote;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class CreditNoteController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum');
    }

    public function index(Request $request): JsonResponse
    {
        $notes = CreditNote::query()
            ->where('tenant_id', $request->user()->tenant_id)
            ->orderByDesc('issued_at')
            ->limit(50)
            ->get(['id', 'number', 'issued_at', 'total_cents']);

        return response()->json(['credit_notes' => $notes]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'reference' => ['required', 'string', 'max:64'],
            'notes' => ['sometimes', 'string', 'max:2000'],
            'total_cents' => ['required', 'integer', 'min:0'],
        ]);

        $data['tenant_id'] = $request->user()->tenant_id;
        $data['issued_at'] = now();

        $note = CreditNote::create($data);

        return response()->json(['credit_note' => $note], 201);
    }

    public function update(Request $request, string $id): JsonResponse
    {
        $note = CreditNote::query()
            ->where('tenant_id', $request->user()->tenant_id)
            ->findOrFail($id);

        $data = $request->validate([
            'reference' => ['sometimes', 'string', 'max:64'],
            'notes' => ['sometimes', 'string', 'max:2000'],
        ]);

        $note->fill($data)->save();

        return response()->json(['credit_note' => $note]);
    }
}
