rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass Stack Frame Check"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 8B 4D 24 52 50 8B 45 28 }  // mov ecx, dword ptr [ebp+24h], pop ecx, mov eax, dword ptr [ebp+28h]

    condition:
        any of them
}