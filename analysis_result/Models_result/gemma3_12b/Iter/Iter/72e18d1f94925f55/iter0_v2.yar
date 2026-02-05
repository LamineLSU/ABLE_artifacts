rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - initial Wine check"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        // mov eax, dword ptr fs:[00000030h]
        // mov eax, dword ptr [eax+68h]
        // shr eax, 08h
        // test al, 01h
        // jne 009B655Ah
    condition:
        any of them
}